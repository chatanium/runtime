package app

import (
	"context"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	runtime "github.com/thirdscam/chatanium/internal/runtime"
	wire "github.com/thirdscam/chatanium/proto/core-v2"
)

func TestDevelopmentFlagsRequireExplicitOptIn(t *testing.T) {
	for _, options := range []StartOptions{
		{DevelopmentSocket: "/private/control.sock"},
		{DevelopmentImages: []string{"module=image"}},
		{DevelopmentMode: true},
		{DevelopmentMode: true, DevelopmentSocket: "relative.sock"},
		{DevelopmentMode: true, DevelopmentSocket: "/private/../control.sock"},
	} {
		if validateDevelopmentOptions(options) == nil {
			t.Fatalf("invalid development options accepted: %#v", options)
		}
		if Start(context.Background(), options) == nil {
			t.Fatal("invalid development options reached runtime startup")
		}
	}
	if err := validateDevelopmentOptions(StartOptions{DevelopmentMode: true, DevelopmentSocket: "/private/control.sock"}); err != nil {
		t.Fatal(err)
	}
}

func TestDevelopmentDisabledCreatesNoControl(t *testing.T) {
	control, err := startDevelopmentController(context.Background(), StartOptions{}, runtime.Config{}, nil)
	if err != nil || control != nil {
		t.Fatal("ordinary startup created development control")
	}
	path := filepath.Join(t.TempDir(), "control.sock")
	if control, err = startDevelopmentController(context.Background(), StartOptions{DevelopmentSocket: path}, runtime.Config{}, nil); err == nil || control != nil {
		t.Fatal("socket option bypassed development opt-in")
	}
}

func TestDevelopmentImageOverridesChangeOnlyImage(t *testing.T) {
	originalImage := "registry.test/team/module@sha256:" + strings.Repeat("1", 64)
	image := "registry.test/team/module@sha256:" + strings.Repeat("2", 64)
	original := runtime.ModuleSpec{
		ModuleID: "module", ImageDigest: originalImage, Entrypoint: []string{"/module"}, Args: []string{"arg"}, UID: 101, GID: 102,
		Config: &wire.JSONValue{Json: []byte(`{"private":"unchanged"}`)}, Approval: &wire.Grants{},
		ConfigRevision: "configuration", ApprovalRevision: "approval",
	}
	config := runtime.Config{Modules: []runtime.ModuleSpec{original}}
	if err := applyDevelopmentImages(&config, []string{"module=" + image}); err != nil {
		t.Fatal(err)
	}
	got := config.Modules[0]
	if got.ImageDigest != image {
		t.Fatal("image override was not applied")
	}
	got.ImageDigest = originalImage
	if !reflect.DeepEqual(got, original) {
		t.Fatal("image override changed approval, configuration or execution identity")
	}
}

func TestDevelopmentImageOverridesRejectMutableForeignAndDuplicateImages(t *testing.T) {
	image := "registry.test/team/module@sha256:" + strings.Repeat("1", 64)
	valid := "module=registry.test/team/module@sha256:" + strings.Repeat("2", 64)
	for _, overrides := range [][]string{
		{"module=registry.test/team/module:latest"},
		{"module=registry.test/team/other@sha256:" + strings.Repeat("2", 64)},
		{"missing=" + image},
		{"module="}, {"=" + image}, {"module"},
		{"module=registry.test/team/module@sha256:" + strings.Repeat("A", 64)},
		{valid, valid}, {valid, "missing=" + image},
	} {
		config := runtime.Config{Modules: []runtime.ModuleSpec{{ModuleID: "module", ImageDigest: image}}}
		if applyDevelopmentImages(&config, overrides) == nil {
			t.Fatalf("unsafe overrides accepted: %v", overrides)
		}
		if config.Modules[0].ImageDigest != image {
			t.Fatal("failed override set partially changed startup images")
		}
	}
}
