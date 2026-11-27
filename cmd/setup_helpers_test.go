//go:build linux

package cmd

import (
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/thirdscam/chatanium/internal/bootstrap"
	"github.com/thirdscam/chatanium/internal/provision"
)

func TestGvxTaskCredentialStreamRequiresOpaqueApprovedReference(t *testing.T) {
	command := &cobra.Command{}
	command.Flags().StringArray("image-input", nil, "")
	command.Flags().StringArray("image-credential", nil, "")
	if err := command.Flags().Set("image-credential", "jobone=/private/operator-credential"); err != nil {
		t.Fatal(err)
	}
	modules := []bootstrap.InitModuleInput{{Image: provision.ApprovedImageInput{JobID: "jobone", SourceKind: "registry"}}}
	if _, _, err := imageInputBindings(command, modules); err == nil {
		t.Fatal("private credential path became authority without a task reference")
	}
	if err := bindDraftCredentialRefs(command, modules); err != nil {
		t.Fatal(err)
	}
	reference := modules[0].Image.CredentialRef
	if !strings.HasPrefix(reference, "task-") || len(reference) != 69 || strings.Contains(reference, "private") {
		t.Fatal("credential reference retained a file path or invalid identity")
	}
	archives, credentials, err := imageInputBindings(command, modules)
	if err != nil || len(archives) != 0 || credentials["jobone"] != "/private/operator-credential" {
		t.Fatal("approved stream binding rejected")
	}
	modules[0].Image.SourceKind = "oci-archive"
	if _, _, err := imageInputBindings(command, modules); err == nil {
		t.Fatal("registry credentials accepted for offline preparation")
	}
}
