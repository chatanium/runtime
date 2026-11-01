package Util

import (
	"os"
	"path/filepath"
	"testing"
)

func TestInitEnvAllowsProvisionedEnvironmentWithoutDotenv(t *testing.T) {
	t.Chdir(t.TempDir())
	t.Setenv("CHATANIUM_ENV_FIXTURE", "provisioned")
	if err := InitEnv(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CHATANIUM_ENV_FIXTURE"); got != "provisioned" {
		t.Fatalf("provisioned value changed to %q", got)
	}
}

func TestInitEnvPreservesProvisionedValues(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	t.Setenv("CHATANIUM_ENV_FIXTURE", "provisioned")
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("CHATANIUM_ENV_FIXTURE=local-default\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitEnv(); err != nil {
		t.Fatal(err)
	}
	if got := os.Getenv("CHATANIUM_ENV_FIXTURE"); got != "provisioned" {
		t.Fatalf("provisioned value overwritten by %q", got)
	}
}

func TestInitEnvRejectsMalformedDotenv(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("BROKEN=\"unterminated\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := InitEnv(); err == nil {
		t.Fatal("malformed dotenv was ignored")
	}
}
