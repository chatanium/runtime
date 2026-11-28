//go:build linux

package cli

import (
	"crypto/rand"
	"encoding/hex"
	"errors"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/legacy/bootstrap"
)

func taskCredentialRef() (string, error) {
	var nonce [32]byte
	if _, err := rand.Read(nonce[:]); err != nil {
		return "", err
	}
	return "task-" + hex.EncodeToString(nonce[:]), nil
}
func taskBindingPaths(cmd *cobra.Command, flag string) (map[string]string, error) {
	values, _ := cmd.Flags().GetStringArray(flag)
	out := make(map[string]string, len(values))
	for _, value := range values {
		job, path, ok := strings.Cut(value, "=")
		if !ok || job == "" || !filepath.IsAbs(path) || filepath.Clean(path) != path || path == "/" || strings.ContainsRune(path, 0) {
			return nil, errors.New("invalid private image input binding")
		}
		if _, duplicate := out[job]; duplicate {
			return nil, errors.New("duplicate private image input binding")
		}
		out[job] = path
	}
	return out, nil
}
func bindDraftCredentialRefs(cmd *cobra.Command, modules []bootstrap.InitModuleInput) error {
	credentials, err := taskBindingPaths(cmd, "image-credential")
	if err != nil {
		return err
	}
	seen := make(map[string]bool, len(credentials))
	for i := range modules {
		image := &modules[i].Image
		if credentials[image.JobID] == "" {
			continue
		}
		if image.SourceKind != "registry" {
			return errors.New("task registry credentials cannot be attached to offline/prepared images")
		}
		seen[image.JobID] = true
		if image.CredentialRef == "" {
			image.CredentialRef, err = taskCredentialRef()
			if err != nil {
				return err
			}
		}
	}
	if len(seen) != len(credentials) {
		return errors.New("credential input refers to an unknown draft preparation job")
	}
	return nil
}
func imageInputBindings(cmd *cobra.Command, modules []bootstrap.InitModuleInput) (map[string]string, map[string]string, error) {
	archives, err := taskBindingPaths(cmd, "image-input")
	if err != nil {
		return nil, nil, err
	}
	credentials, err := taskBindingPaths(cmd, "image-credential")
	if err != nil {
		return nil, nil, err
	}
	jobs := make(map[string]bool, len(modules))
	for _, module := range modules {
		image := module.Image
		if image.SourceKind == "prepared" {
			if image.CredentialRef != "" {
				return nil, nil, errors.New("prepared records cannot carry registry credentials")
			}
			continue
		}
		job := image.JobID
		if job == "" || jobs[job] {
			return nil, nil, errors.New("preparation jobs must have unique explicit identities")
		}
		jobs[job] = true
		hasArchive, hasCredential := archives[job] != "", credentials[job] != ""
		switch image.SourceKind {
		case "registry":
			if hasArchive || hasCredential != (image.CredentialRef != "") {
				return nil, nil, errors.New("registry input streams differ from the approved task bindings")
			}
		case "oci-archive", "docker-archive":
			if !hasArchive || hasCredential || image.CredentialRef != "" {
				return nil, nil, errors.New("offline preparation requires archive input and forbids registry credentials")
			}
		default:
			return nil, nil, errors.New("unsupported preparation source")
		}
	}
	for _, bindings := range []map[string]string{archives, credentials} {
		for job := range bindings {
			if !jobs[job] {
				return nil, nil, errors.New("private input refers to an unapproved preparation job")
			}
		}
	}
	return archives, credentials, nil
}
