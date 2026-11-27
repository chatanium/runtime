package provision

import (
	"archive/tar"
	"bytes"
	"context"
	"crypto/sha256"
	"debug/elf"
	"encoding/binary"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"github.com/thirdscam/chatanium/internal/bundle"
)

const DevelopmentMetadataMax = 1 << 20

type DevelopmentWorkerTask struct {
	Input     bundle.DevelopmentWorkerInput `json:"input"`
	Directory string                        `json:"directory"`
	BaseRoot  string                        `json:"base_root"`
	Limits    PrepareLimits                 `json:"limits"`
}

func ValidateDevelopmentInput(in bundle.DevelopmentWorkerInput) error {
	if !ValidDigest(in.ArchiveDigest) || in.ArchiveBytes <= 0 || in.ArchiveBytes > bundle.MaxBundleBytes || in.ArchiveBytes%4096 != 0 {
		return errors.New("invalid bounded development artifact identity")
	}
	return nil
}
func runDevelopmentWorker(ctx context.Context, t DevelopmentWorkerTask, input io.Reader, out io.Writer) error {
	if e := ValidateDevelopmentInput(t.Input); e != nil {
		return e
	}
	if e := t.Limits.Validate(); e != nil {
		return e
	}
	if t.Limits.InputBytes != t.Input.ArchiveBytes || t.Limits.ExpandedBytes != t.Input.ArchiveBytes || t.Limits.OutputBytes != t.Input.ArchiveBytes || !filepath.IsAbs(t.Directory) || filepath.Clean(t.Directory) != t.Directory || !filepath.IsAbs(t.BaseRoot) || filepath.Clean(t.BaseRoot) != t.BaseRoot {
		return errors.New("development task bounds or owned paths mismatch")
	}
	ctx, cancel := context.WithTimeout(ctx, t.Limits.Deadline)
	defer cancel()
	baseRaw, e := preparerRead(filepath.Join(t.BaseRoot, "manifest.json"), bundle.MaxManifestBytes)
	if e != nil {
		return e
	}
	base, e := bundle.VerifyManifest(baseRaw)
	if e != nil {
		return e
	}
	h := sha256.New()
	lr := &io.LimitedReader{R: io.TeeReader(input, h), N: t.Input.ArchiveBytes + 1}
	tr := tar.NewReader(lr)
	header, e := tr.Next()
	if e != nil {
		return e
	}
	if e = developmentHeader(header, "worker-manifest.json", 0444); e != nil {
		return e
	}
	if header.Size <= 0 || header.Size > DevelopmentMetadataMax {
		return errors.New("development manifest exceeds bound")
	}
	raw, e := io.ReadAll(io.LimitReader(tr, DevelopmentMetadataMax+1))
	if e != nil {
		return e
	}
	manifest, e := bundle.VerifyDevelopmentWorkerManifest(raw, base)
	if e != nil {
		return e
	}
	if len(manifest.Files) == 0 || len(manifest.Files) > 4096 {
		return errors.New("development inventory exceeds bound")
	}
	if e = os.WriteFile(filepath.Join(t.Directory, "worker-manifest.json"), raw, 0600); e != nil {
		return e
	}
	directories := map[string]bool{".": true}
	inodes := int64(2)
	total := int64(len(raw))
	previous := ""
	for _, file := range manifest.Files {
		if e = ctx.Err(); e != nil {
			return e
		}
		if file.Path <= previous || !safeName(file.Path) || file.Size < 0 || !ValidDigest(file.Digest) {
			return errors.New("invalid ordered development inventory")
		}
		previous = file.Path
		header, e = tr.Next()
		if e != nil {
			return e
		}
		if e = developmentHeader(header, file.Path, file.Mode); e != nil {
			return e
		}
		if header.Size != file.Size {
			return errors.New("development file descriptor size mismatch")
		}
		total += file.Size
		if total > t.Limits.OutputBytes {
			return errors.New("development output byte bound exceeded")
		}
		parent := path.Dir(file.Path)
		var missing []string
		for parent != "." && !directories[parent] {
			missing = append(missing, parent)
			parent = path.Dir(parent)
		}
		for i := len(missing) - 1; i >= 0; i-- {
			dir := missing[i]
			inodes++
			if inodes > t.Limits.Inodes {
				return errors.New("development inode bound exceeded")
			}
			if e = os.Mkdir(filepath.Join(t.Directory, filepath.FromSlash(dir)), 0700); e != nil {
				return e
			}
			directories[dir] = true
		}
		inodes++
		if inodes > t.Limits.Inodes {
			return errors.New("development inode bound exceeded")
		}
		destination := filepath.Join(t.Directory, filepath.FromSlash(file.Path))
		f, e := os.OpenFile(destination, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if e != nil {
			return e
		}
		digest := sha256.New()
		n, e := io.Copy(io.MultiWriter(f, digest), tr)
		if e == nil && (n != file.Size || "sha256:"+hex.EncodeToString(digest.Sum(nil)) != file.Digest) {
			e = errors.New("development member integrity mismatch")
		}
		if e == nil {
			e = f.Sync()
		}
		e = errors.Join(e, f.Close())
		if e != nil {
			return e
		}
	}
	if _, e = tr.Next(); e != io.EOF {
		return errors.New("development artifact has extra archive entries")
	}
	buf := make([]byte, 32<<10)
	for {
		n, e := lr.Read(buf)
		for _, b := range buf[:n] {
			if b != 0 {
				return errors.New("development artifact has nonzero trailing bytes")
			}
		}
		if e == io.EOF {
			break
		}
		if e != nil {
			return e
		}
	}
	if t.Input.ArchiveBytes+1-lr.N != t.Input.ArchiveBytes || "sha256:"+hex.EncodeToString(h.Sum(nil)) != t.Input.ArchiveDigest {
		return errors.New("development archive exact identity mismatch")
	}
	if e = verifyDevelopmentELF(ctx, t.Directory, manifest, t.BaseRoot, base, t.Limits); e != nil {
		return e
	}
	encoded, e := json.Marshal(manifest)
	if e != nil {
		return e
	}
	if len(encoded) > DevelopmentMetadataMax {
		return errors.New("development output metadata exceeds bound")
	}
	_, e = out.Write(encoded)
	return e
}
func developmentHeader(h *tar.Header, name string, mode uint32) error {
	if h.Name != name || h.Format != tar.FormatUSTAR || h.Typeflag != tar.TypeReg || h.Size < 0 || h.Linkname != "" || h.Uid != 0 || h.Gid != 0 || h.Uname != "" || h.Gname != "" || h.Mode != int64(mode) || len(h.PAXRecords) != 0 || len(h.Xattrs) != 0 {
		return errors.New("unsupported development USTAR member")
	}
	return nil
}

type developmentELF struct {
	needed      []string
	required    map[string][]string
	provided    map[string]bool
	interpreter string
	soname      string
	dynamic     bool
}

func inspectDevelopmentELF(file string, worker bool, voice bool, l PrepareLimits) (developmentELF, error) {
	var result developmentELF
	f, e := elf.Open(file)
	if e != nil {
		return result, e
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Data != elf.ELFDATA2LSB || f.Machine != elf.EM_X86_64 || f.Type != elf.ET_DYN && f.Type != elf.ET_EXEC || len(f.Sections) > 4096 || len(f.Progs) > 512 {
		return result, errors.New("development ELF architecture/type bounds mismatch")
	}
	for _, section := range f.Sections {
		metadata := section.Name == ".dynstr" || section.Name == ".dynamic" || section.Name == ".gnu.version_d" || section.Name == ".gnu.version_r"
		if metadata && (section.Flags&elf.SHF_COMPRESSED != 0 || section.Size > uint64(l.JSONBytes)) {
			return result, errors.New("compressed or oversized development ELF loader metadata")
		}
	}
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			if result.interpreter != "" || p.Filesz == 0 || p.Filesz > 4096 {
				return result, errors.New("invalid candidate interpreter metadata")
			}
			b, e := io.ReadAll(io.LimitReader(p.Open(), 4097))
			if e != nil {
				return result, e
			}
			if len(b) == 0 || b[len(b)-1] != 0 || bytes.IndexByte(b[:len(b)-1], 0) >= 0 {
				return result, errors.New("noncanonical ELF interpreter")
			}
			result.interpreter = string(b[:len(b)-1])
		}
		if p.Type == elf.PT_DYNAMIC {
			result.dynamic = true
		}
	}
	if worker {
		if !voice && (result.interpreter != "" || result.dynamic) {
			return result, errors.New("voice-disabled development worker must be static")
		}
		if voice && result.interpreter != "/lib64/ld-linux-x86-64.so.2" {
			return result, errors.New("voice worker interpreter is not the installed EL9 ABI")
		}
	} else if result.interpreter != "" || f.Type != elf.ET_DYN {
		return result, errors.New("candidate library must be an uninterpreted shared ELF")
	}
	for _, tag := range []elf.DynTag{elf.DT_RPATH, elf.DT_RUNPATH} {
		paths, e := f.DynString(tag)
		if e != nil {
			return result, e
		}
		for _, list := range paths {
			for _, entry := range strings.Split(list, ":") {
				allowed := entry == "$ORIGIN" && !worker || entry == "$ORIGIN/voice-runtime/lib" && worker
				if !allowed {
					return result, errors.New("unconfined candidate loader search metadata")
				}
			}
		}
	}
	result.needed, e = f.DynString(elf.DT_NEEDED)
	if e != nil {
		return result, e
	}
	for _, name := range result.needed {
		if name == "" || name != path.Base(name) || strings.ContainsAny(name, "\\\x00") {
			return result, errors.New("unconfined ELF dependency")
		}
	}
	sonames, e := f.DynString(elf.DT_SONAME)
	if e != nil {
		return result, e
	}
	if len(sonames) > 1 {
		return result, errors.New("ambiguous ELF soname")
	}
	if len(sonames) == 1 {
		result.soname = sonames[0]
	}
	result.required, result.provided, e = developmentELFVersions(f, l)
	return result, e
}
func versionString(table []byte, offset uint32) (string, error) {
	if uint64(offset) >= uint64(len(table)) {
		return "", errors.New("ELF version string outside table")
	}
	b := table[offset:]
	n := bytes.IndexByte(b, 0)
	if n < 1 || n > 4096 {
		return "", errors.New("invalid ELF version string")
	}
	return string(b[:n]), nil
}
func developmentELFVersions(f *elf.File, l PrepareLimits) (map[string][]string, map[string]bool, error) {
	required := map[string][]string{}
	provided := map[string]bool{}
	section := f.Section(".dynstr")
	if section == nil {
		return required, provided, nil
	}
	stringsTable, e := section.Data()
	if e != nil {
		return nil, nil, e
	}
	order := binary.LittleEndian
	entries := int64(0)
	if definitions := f.Section(".gnu.version_d"); definitions != nil {
		b, e := definitions.Data()
		if e != nil {
			return nil, nil, e
		}
		for offset, count := uint32(0), int64(0); ; count++ {
			entries++
			if entries > l.DescriptorCount || count > l.DescriptorCount || uint64(offset)+20 > uint64(len(b)) {
				return nil, nil, errors.New("invalid bounded ELF version definitions")
			}
			d := b[offset:]
			if order.Uint16(d) != 1 {
				return nil, nil, errors.New("unsupported ELF version definition")
			}
			aux := order.Uint32(d[12:])
			if uint64(offset)+uint64(aux)+8 > uint64(len(b)) {
				return nil, nil, errors.New("ELF definition auxiliary outside section")
			}
			name, e := versionString(stringsTable, order.Uint32(b[offset+aux:]))
			if e != nil {
				return nil, nil, e
			}
			provided[name] = true
			next := order.Uint32(d[16:])
			if next == 0 {
				break
			}
			if next < 20 || uint64(offset)+uint64(next) > uint64(len(b)) {
				return nil, nil, errors.New("invalid ELF definition chain")
			}
			offset += next
		}
	}
	if needs := f.Section(".gnu.version_r"); needs != nil {
		b, e := needs.Data()
		if e != nil {
			return nil, nil, e
		}
		for offset, count := uint32(0), int64(0); ; count++ {
			if count > l.DescriptorCount || uint64(offset)+16 > uint64(len(b)) {
				return nil, nil, errors.New("invalid bounded ELF version requirements")
			}
			d := b[offset:]
			if order.Uint16(d) != 1 {
				return nil, nil, errors.New("unsupported ELF version need")
			}
			library, e := versionString(stringsTable, order.Uint32(d[4:]))
			if e != nil {
				return nil, nil, e
			}
			aux := order.Uint32(d[8:])
			number := order.Uint16(d[2:])
			entries += int64(number) + 1
			if entries > l.DescriptorCount {
				return nil, nil, errors.New("ELF version requirement count exceeded")
			}
			for i := uint16(0); i < number; i++ {
				if uint64(offset)+uint64(aux)+16 > uint64(len(b)) {
					return nil, nil, errors.New("ELF requirement auxiliary outside section")
				}
				a := b[offset+aux:]
				version, e := versionString(stringsTable, order.Uint32(a[8:]))
				if e != nil {
					return nil, nil, e
				}
				required[library] = append(required[library], version)
				next := order.Uint32(a[12:])
				if i+1 < number {
					if next < 16 || uint64(aux)+uint64(next) > uint64(len(b)) {
						return nil, nil, errors.New("invalid ELF requirement chain")
					}
					aux += next
				}
			}
			next := order.Uint32(d[12:])
			if next == 0 {
				break
			}
			if next < 16 || uint64(offset)+uint64(next) > uint64(len(b)) {
				return nil, nil, errors.New("invalid ELF need chain")
			}
			offset += next
		}
	}
	return required, provided, nil
}
func verifyDevelopmentELF(ctx context.Context, root string, m bundle.DevelopmentWorkerManifest, baseRoot string, base bundle.Manifest, l PrepareLimits) error {
	candidate := map[string]string{}
	for _, file := range m.Files {
		if strings.HasPrefix(file.Path, "bin/voice-runtime/lib/") {
			candidate[path.Base(file.Path)] = filepath.Join(root, filepath.FromSlash(file.Path))
		}
	}
	if !m.Voice && len(candidate) != 0 {
		return errors.New("static worker artifact contains native libraries")
	}
	baseLibraries := map[string]string{}
	for _, file := range base.Files {
		if strings.HasPrefix(file.Path, "lib/") && path.Dir(file.Path) == "lib" {
			baseLibraries[path.Base(file.Path)] = filepath.Join(baseRoot, filepath.FromSlash(file.Path))
		}
	}
	type item struct {
		name, file        string
		worker, candidate bool
	}
	queue := []item{{name: "chatanium-worker", file: filepath.Join(root, "bin/chatanium-worker"), worker: true, candidate: true}}
	var names []string
	for name := range candidate {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		queue = append(queue, item{name: name, file: candidate[name], candidate: true})
	}
	seen := map[string]developmentELF{}
	providers := map[string]developmentELF{}
	for len(queue) > 0 {
		if e := ctx.Err(); e != nil {
			return e
		}
		it := queue[0]
		queue = queue[1:]
		if _, ok := seen[it.file]; ok {
			continue
		}
		if int64(len(seen)) > l.DescriptorCount {
			return errors.New("native dependency closure count exceeded")
		}
		var info developmentELF
		var e error
		if it.candidate {
			info, e = inspectDevelopmentELF(it.file, it.worker, m.Voice, l)
		} else {
			info, e = inspectBaseDevelopmentELF(it.file, l)
		}
		if e != nil {
			return fmt.Errorf("development ELF %s: %w", it.name, e)
		}
		if it.candidate && !it.worker && info.soname != "" && info.soname != it.name {
			return errors.New("candidate library name and SONAME differ")
		}
		seen[it.file] = info
		providers[it.name] = info
		for _, needed := range info.needed {
			if file, ok := candidate[needed]; ok {
				queue = append(queue, item{name: needed, file: file, candidate: true})
			} else if file, ok := baseLibraries[needed]; ok {
				queue = append(queue, item{name: needed, file: file})
			} else {
				return errors.New("development ELF dependency missing from candidate/base closure")
			}
		}
	}
	for _, info := range seen {
		needed := map[string]bool{}
		for _, name := range info.needed {
			needed[name] = true
		}
		for library, versions := range info.required {
			provider, ok := providers[library]
			if !ok || !needed[library] {
				return errors.New("versioned dependency lacks declared provider")
			}
			for _, version := range versions {
				if !provider.provided[version] {
					return errors.New("development ELF requires unavailable dependency version")
				}
			}
		}
	}
	return nil
}
func inspectBaseDevelopmentELF(file string, l PrepareLimits) (developmentELF, error) {
	// Base is independently verified installed code, not candidate authority. Its
	// search metadata need not be rewritten; only dependency/version closure is read.
	var info developmentELF
	f, e := elf.Open(file)
	if e != nil {
		return info, e
	}
	defer f.Close()
	if f.Class != elf.ELFCLASS64 || f.Machine != elf.EM_X86_64 {
		return info, errors.New("base native ABI mismatch")
	}
	for _, s := range f.Sections {
		if (s.Name == ".dynstr" || s.Name == ".gnu.version_r" || s.Name == ".gnu.version_d") && s.Size > uint64(l.JSONBytes) {
			return info, errors.New("base ELF version metadata exceeds bound")
		}
	}
	info.needed, e = f.DynString(elf.DT_NEEDED)
	if e != nil {
		return info, e
	}
	info.required, info.provided, e = developmentELFVersions(f, l)
	return info, e
}
