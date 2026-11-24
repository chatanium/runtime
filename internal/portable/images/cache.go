package images

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"

	"github.com/thirdscam/chatanium/internal/provision"
)

// Generation is a receipt for one read-only cache, not an approval. The
// caller persists this under the installation's owner lock and retains the
// same storage epoch across worker/supervisor restarts.
type Generation struct {
	ID                string                    `json:"id"`
	Digest            string                    `json:"digest"`
	Epoch             string                    `json:"epoch"`
	PlanDigest        string                    `json:"plan_digest"`
	SourceDigest      string                    `json:"source_digest"`
	ManifestDigest    string                    `json:"manifest_digest"`
	DeclarationDigest string                    `json:"declaration_digest"`
	ExecutionRef      string                    `json:"execution_ref"`
	Directory         string                    `json:"directory"`
	Architecture      string                    `json:"architecture"`
	Format            string                    `json:"format"`
	Declaration       []byte                    `json:"declaration"`
	ImageEnv          []string                  `json:"image_env"`
	Entrypoint        []string                  `json:"entrypoint"`
	Cmd               []string                  `json:"cmd"`
	Workdir           string                    `json:"workdir"`
	Layers            []provision.LayerRecord   `json:"layers"`
	Files             []provision.FileIntegrity `json:"files"`
}

func (g Generation) identity() (string, error) {
	g.Digest = ""
	b, err := json.Marshal(g)
	if err != nil {
		return "", err
	}
	return provision.DomainDigest("chatanium-portable-image-generation-v2", b), nil
}

func (g Generation) ReviewDigest(grant any) (string, error) {
	digest, err := g.identity()
	if err != nil {
		return "", err
	}
	if digest != g.Digest || grant == nil {
		return "", errors.New("invalid image generation or omitted review grant")
	}
	b, err := json.Marshal(struct {
		ResourceVersion string `json:"resource_version"`
		Image           string `json:"generation_digest"`
		Grant           any    `json:"grant"`
	}{ResourceVersion, digest, grant})
	if err != nil {
		return "", err
	}
	return provision.DomainDigest("chatanium-portable-module-review-v2", b), nil
}

// LaunchImage supplies engine image inputs, not module arguments. The caller
// must run in a private empty working directory, use --pull=never and keep
// stock GVX host lockdown enabled. Its per-run cache may contain hardlinks to
// the frozen files (without changing permissions) and a distinct scratch dir.
type LaunchImage struct {
	Directory, ExecutionRef, RegistryURL string
}

// canonicalMetadata is the pinned engine's pre-lockdown input boundary.
// initOCILayers resolves relative archive paths (the caller supplies a private
// cwd), parses cache JSON + manifest/config JSON, validates .sum records and
// opens/hashes layers. None of those documents, names or path fields come from
// the compiler's cache or raw source OCI. Only validated digest/size/media
// scalars cross into the fixed schema below. Runtime config fields, including
// env, user, command and cwd, are deliberately absent. The first EROFS
// structural parse is mountEROFSLowerLayers in guest boot, after lockdown.
// https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/gvx/image.go#L135-L259
// https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/oci/cache.go#L240-L289
// https://github.com/gfire-sigs/gvx/blob/a90476e02630e7d35861e1da16d407e03e71e8b7/pkg/gvx/boot_vfs.go#L319-L351
// Existing ext4lite volumes are a separate trust input: GVX opens and replays
// their journals before lockdown. Only engine-created, installation-owned
// volumes with checked identity/bounds are admissible; no raw backing device,
// externally supplied image, or host-writable bind is part of this contract.
func canonicalMetadata(arch, format string, layers []provision.LayerRecord) (name, ref string, raw []byte, err error) {
	if (arch != "amd64" && arch != "arm64") || format != cacheFormat() || len(layers) == 0 || len(layers) > 4096 {
		return "", "", nil, errors.New("invalid portable cache platform or layer count")
	}
	type descriptor struct {
		MediaType string `json:"mediaType"`
		Digest    string `json:"digest"`
		Size      int64  `json:"size"`
	}
	type configRoot struct {
		Type    string   `json:"type"`
		DiffIDs []string `json:"diff_ids"`
	}
	config := struct {
		OS           string     `json:"os"`
		Architecture string     `json:"architecture"`
		RootFS       configRoot `json:"rootfs"`
	}{"linux", arch, configRoot{"layers", make([]string, len(layers))}}
	manifest := struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Config        descriptor   `json:"config"`
		Layers        []descriptor `json:"layers"`
	}{SchemaVersion: 2, MediaType: "application/vnd.oci.image.manifest.v1+json", Layers: make([]descriptor, len(layers))}
	for i, l := range layers {
		if !provision.ValidDigest(l.DiffID) || !provision.ValidDigest(l.Digest) || l.Size <= 0 || l.Size > 1<<40 {
			return "", "", nil, errors.New("invalid portable cache layer")
		}
		// The manifest is used only to index compiled EROFS with --pull=never.
		// Keep a canonical supported media type, independent of raw OCI fields.
		manifest.Layers[i] = descriptor{"application/vnd.oci.image.layer.v1.tar", l.Digest, l.Size}
		config.RootFS.DiffIDs[i] = l.DiffID
	}
	cb, err := json.Marshal(config)
	if err != nil {
		return "", "", nil, err
	}
	manifest.Config = descriptor{"application/vnd.oci.image.config.v1+json", provision.Digest(cb), int64(len(cb))}
	mb, err := json.Marshal(manifest)
	if err != nil {
		return "", "", nil, err
	}
	digest := provision.Digest(mb)
	const repository = "module-cache"
	name = "image-" + provision.CacheKey(format, RegistryURL, repository, digest, arch) + ".json"
	raw, err = json.Marshal(provision.CacheImageRecord{Version: 2, BaseURL: RegistryURL, Repository: repository, Digest: digest, Architecture: arch, Format: format, Manifests: [][]byte{mb}, Config: cb, Source: "archive"})
	return name, provision.ExecutionRef(digest), raw, err
}

func layerName(digest, format string) string { return digest[7:] + "." + format + ".erofs" }

func syncDir(root *os.Root, name string) error {
	f, err := root.Open(name)
	if err != nil {
		return err
	}
	// Windows does not expose directory fsync through os.File. Individual
	// files are flushed and activation is journaled by the caller's store.
	if runtime.GOOS == "windows" {
		return f.Close()
	}
	return errors.Join(f.Sync(), f.Close())
}

func imageDirectoryIdentity(root *os.Root, name string) (os.FileInfo, error) {
	if err := directoryNoLinks(root, name); err != nil {
		return nil, err
	}
	f, err := root.Open(name)
	if err != nil {
		return nil, err
	}
	info, statErr := f.Stat() // Windows needs the file ID, not a lazy path lookup after rename.
	if err = errors.Join(statErr, f.Close()); err != nil {
		return nil, err
	}
	if !info.IsDir() || !plainEntry(info) {
		return nil, errors.New("cache promotion requires a real directory")
	}
	return info, nil
}

func createFrozen(root *os.Root, name string, src io.Reader, size int64) (provision.FileIntegrity, error) {
	var out provision.FileIntegrity
	f, err := root.OpenFile(name, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0600)
	if err != nil {
		return out, err
	}
	h := sha256.New()
	_, err = io.CopyN(io.MultiWriter(f, h), src, size)
	if err == nil {
		err = errors.Join(f.Chmod(0444), f.Sync())
	}
	if err = errors.Join(err, f.Close()); err != nil {
		return out, err
	}
	return provision.FileIntegrity{Path: filepath.Base(name), Digest: "sha256:" + hex.EncodeToString(h.Sum(nil)), Size: size, Mode: 0444}, nil
}

func freezeBytes(root *os.Root, directory, name string, data []byte) (provision.FileIntegrity, error) {
	return createFrozen(root, filepath.Join(directory, name), bytes.NewReader(data), int64(len(data)))
}

func generationPath(epoch, id string) string { return path.Join("images", epoch, id) }

func directoryNoLinks(root *os.Root, name string) error {
	current := ""
	for part := range strings.SplitSeq(filepath.ToSlash(name), "/") {
		if part == "" || part == "." || part == ".." {
			return errors.New("invalid installation directory component")
		}
		current = filepath.Join(current, part)
		info, err := root.Lstat(current)
		if err != nil {
			return err
		}
		if !info.IsDir() || !plainEntry(info) {
			return errors.New("installation path is not an owned directory")
		}
	}
	return nil
}

func (g Generation) checkPath(epoch string) error {
	if !addressedID(epoch) || !addressedID(g.ID) || g.Epoch != epoch || g.Directory != generationPath(epoch, g.ID) {
		return errors.New("image generation is not owned by this installation epoch")
	}
	return nil
}

func (g Generation) VerifiedLaunch(root *os.Root, epoch string) (LaunchImage, error) {
	var zero LaunchImage
	if root == nil || !checkedPath(root.Name()) || g.Architecture != runtime.GOARCH || g.Format != cacheFormat() {
		return zero, errors.New("missing installation root or incompatible cache target")
	}
	if err := g.checkPath(epoch); err != nil {
		return zero, err
	}
	digest, err := g.identity()
	if err != nil || digest != g.Digest || provision.Digest(g.Declaration) != g.DeclarationDigest {
		return zero, errors.New("image generation receipt mismatch")
	}
	name, ref, meta, err := canonicalMetadata(g.Architecture, g.Format, g.Layers)
	if err != nil || g.ExecutionRef != ref {
		return zero, errors.New("invalid generated cache reference")
	}
	if err = directoryNoLinks(root, g.Directory); err != nil {
		return zero, err
	}
	d, err := root.OpenRoot(g.Directory)
	if err != nil {
		return zero, err
	}
	defer d.Close()
	directory, err := d.Stat(".")
	if err != nil || !directory.IsDir() || runtime.GOOS != "windows" && directory.Mode().Perm()&0222 != 0 {
		return zero, errors.New("image cache directory is not read-only")
	}
	block, err := provision.CacheBlockSize(g.Format)
	if err != nil {
		return zero, err
	}
	want := make(map[string]provision.FileIntegrity, len(g.Files))
	for _, f := range g.Files {
		if !provision.ValidDigest(f.Digest) || f.Mode != 0444 || f.Size <= 0 || f.Size > 1<<40 || filepath.Base(f.Path) != f.Path || f.Path == "." || f.Path == ".." || strings.ContainsAny(f.Path, "/\\:\x00") || want[f.Path].Path != "" {
			return zero, errors.New("invalid immutable cache inventory")
		}
		want[f.Path] = f
	}
	if f := want[name]; f.Digest != provision.Digest(meta) || f.Size != int64(len(meta)) {
		return zero, errors.New("cache metadata was not generated by this release")
	}
	count := 1
	seen := make(map[string]bool, len(g.Layers))
	for _, layer := range g.Layers {
		if seen[layer.Digest] {
			continue
		}
		seen[layer.Digest] = true
		path := layerName(layer.Digest, g.Format)
		f, ok := want[path]
		if !ok || f.Size < int64(block) || f.Size%int64(block) != 0 {
			return zero, errors.New("missing or invalid compiled image layer")
		}
		sum := []byte(fmt.Sprintf("%s %d %s\n", g.Format, f.Size, f.Digest[7:]))
		if side := want[path+".sum"]; side.Digest != provision.Digest(sum) || side.Size != int64(len(sum)) {
			return zero, errors.New("noncanonical compiled layer sidecar")
		}
		count += 2
	}
	if len(want) != count {
		return zero, errors.New("unexpected files in cache inventory")
	}
	dir, err := d.Open(".")
	if err != nil {
		return zero, err
	}
	entries, err := dir.ReadDir(count + 1)
	if closeErr := dir.Close(); closeErr != nil {
		return zero, closeErr
	}
	if err != nil && err != io.EOF {
		return zero, err
	}
	if len(entries) != count {
		return zero, errors.New("cache has extra or missing files")
	}
	for _, entry := range entries {
		f, ok := want[entry.Name()]
		if !ok {
			return zero, errors.New("unexpected file in immutable cache")
		}
		if err = verifyFile(d, f); err != nil {
			return zero, err
		}
	}
	return LaunchImage{Directory: filepath.Join(root.Name(), g.Directory), ExecutionRef: ref, RegistryURL: RegistryURL}, nil
}

func verifyFile(root *os.Root, want provision.FileIntegrity) error {
	info, err := root.Lstat(want.Path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || !plainEntry(info) || info.Mode().Perm()&0222 != 0 || info.Size() != want.Size {
		return errors.New("unexpected cache file type, mode or size")
	}
	f, err := root.Open(want.Path)
	if err != nil {
		return err
	}
	defer f.Close()
	if now, err := f.Stat(); err != nil || !os.SameFile(info, now) {
		return errors.New("cache file identity changed during verification")
	}
	h := sha256.New()
	n, err := io.Copy(h, io.LimitReader(f, want.Size+1))
	if err != nil {
		return err
	}
	if n != want.Size || "sha256:"+hex.EncodeToString(h.Sum(nil)) != want.Digest {
		return errors.New("immutable cache content mismatch")
	}
	return nil
}

// Remove retires only a generation in the current owner's approved purge
// scope. A linked generation or member is never traversed or chmodded.
func (g Generation) Remove(root *os.Root, epoch string) error {
	if root == nil {
		return errors.New("installation root required")
	}
	if err := g.checkPath(epoch); err != nil {
		return err
	}
	if err := directoryNoLinks(root, g.Directory); errors.Is(err, fs.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	d, err := root.OpenRoot(g.Directory)
	if err != nil {
		return err
	}
	if err = d.Chmod(".", 0700); err != nil {
		d.Close()
		return err
	}
	if runtime.GOOS == "windows" {
		// Windows requires clearing the read-only attribute to delete a file.
		// Only known regular files may be touched; a reparse point is rejected.
		for _, f := range g.Files {
			if !fs.ValidPath(f.Path) || filepath.Base(f.Path) != f.Path || strings.ContainsAny(f.Path, "/\\:\x00") || f.Path == "." || f.Path == ".." {
				d.Close()
				return errors.New("invalid file in cache purge")
			}
			info, err := d.Lstat(f.Path)
			if errors.Is(err, fs.ErrNotExist) {
				continue
			}
			if err != nil || !info.Mode().IsRegular() || !plainEntry(info) {
				d.Close()
				return errors.New("unsafe cache purge member")
			}
			if err = d.Chmod(f.Path, 0600); err != nil {
				d.Close()
				return err
			}
		}
	}
	if err = d.Close(); err != nil {
		return err
	}
	return root.RemoveAll(g.Directory)
}

func sortInventory(files []provision.FileIntegrity) {
	slices.SortFunc(files, func(a, b provision.FileIntegrity) int { return strings.Compare(a.Path, b.Path) })
}
