//go:build linux

package app

import (
	"strings"
	"testing"
)

func TestStrictOperatorJSONRejectsAmbiguousDocuments(t *testing.T) {
	for _, raw := range []string{`{"application_id":"1","application_id":"2"}`, `{"http":{"json_max_bytes":1,"json_max_bytes":2}}`, `{"unknown_field":true}`, `{} {}`, `{"http":[}`} {
		var out DiscordOperatorConfig
		if StrictJSON([]byte(raw), &out) == nil {
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
	secrets := map[string]string{"discord:bot_token": value}
	got, err := HostSecret(secrets, "discord:bot_token")
	if err != nil || got != value {
		t.Fatal("explicit worker secret binding failed")
	}
	for _, source := range []string{name, "env:" + name, "file:/tmp/secret", "", "discord:missing"} {
		got, err = HostSecret(secrets, source)
		if err == nil || got != "" {
			t.Fatal("unsupported or missing secret source accepted")
		}
		if strings.Contains(err.Error(), value) {
			t.Fatal("secret leaked into diagnostics")
		}
	}
}
