package app

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestStrictOperatorJSONRejectsAmbiguousDocuments(t *testing.T) {
	for _, raw := range []string{`{"application_id":"1","application_id":"2"}`, `{"http":{"json_max_bytes":1,"json_max_bytes":2}}`, `{"unknown_field":true}`, `{} {}`, `{"http":[}`} {
		var out discordOperatorConfig
		if strictJSON([]byte(raw), &out) == nil {
			t.Fatal("ambiguous or unsupported operator JSON accepted")
		}
	}
}

func TestSecretScanDecodesEscapesAndNestedKeys(t *testing.T) {
	secret := "private-fixture-value"
	for _, raw := range []string{`{"nested":[{"value":"private-fixture-value"}]}`, `{"value":"private\u002dfixture-value"}`, `{"private-fixture-value":true}`} {
		if !containsSecretJSON([]byte(raw), []string{secret}) {
			t.Fatal("nested or escaped host secret bypassed module config boundary")
		}
	}
	if containsSecretJSON([]byte(`{"value":"ordinary user content","n":9007199254740993}`), []string{secret}) {
		t.Fatal("safe module config rejected")
	}
}

func TestHostSecretSourcesAreExplicitAndDiagnosticsAreSafe(t *testing.T) {
	const name = "FLEXMODULE_TEST_HOST_SECRET"
	const value = "not-a-real-credential"
	t.Setenv(name, value)
	got, err := hostSecret("env:" + name)
	if err != nil || got != value {
		t.Fatal("explicit host environment binding failed")
	}
	for _, source := range []string{name, "file:/tmp/secret", "env:", "env:../secret", "env:MISSING_FLEXMODULE_TEST_SECRET"} {
		got, err = hostSecret(source)
		if err == nil || got != "" {
			t.Fatal("unsupported or missing secret source accepted")
		}
		if strings.Contains(err.Error(), value) {
			t.Fatal("secret leaked into diagnostics")
		}
	}
}

func TestOperatorFileRejectsSymlinkAndWritableInput(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.json")
	if err := os.WriteFile(path, []byte(`{}`), 0600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(dir, "link.json")
	if err := os.Symlink(path, link); err != nil {
		t.Fatal(err)
	}
	if _, err := readOperatorFile(link); err == nil {
		t.Fatal("operator config symlink accepted")
	}
	if err := os.Chmod(path, 0620); err != nil {
		t.Fatal(err)
	}
	if _, err := readOperatorFile(path); err == nil {
		t.Fatal("group-writable operator config accepted")
	}
}
