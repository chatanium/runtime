package sandbox

import (
	"fmt"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"github.com/thirdscam/chatanium/internal/portable/engine"
)

func TestStartupDiagnosticsEscapeRedactAndStopBeforeModule(t *testing.T) {
	var log startupLog
	token := strings.Repeat("ab", 32)
	_, _ = log.Write([]byte(strings.Repeat("p", startupLogBytes) + "\n"))
	_, _ = log.Write([]byte("control_token=" + token[:24]))
	_, _ = log.Write([]byte(token[24:] + "\nGVX startup: \x1b[2Jfailed\r\n"))
	log.stop()
	_, _ = log.Write([]byte("untrusted-module-output\n"))
	got := log.quoted()
	for _, want := range []string{"control_token=[redacted]", "GVX startup:", `\x1b[2J`, `\n`} {
		if !strings.Contains(got, want) {
			t.Fatalf("missing %q in safe diagnostic: %q", want, got)
		}
	}
	for _, forbidden := range []string{token[:24], "untrusted-module-output", strings.Repeat("p", 32), "\x1b", "\r", "\n"} {
		if strings.Contains(got, forbidden) {
			t.Fatalf("unsafe startup diagnostic: %q", got)
		}
	}
	if reason := startupReason(fmt.Errorf("sensitive launch data: %w", engine.ErrCapabilityMissing)); reason != "ENGINE_CAPABILITY_MISSING" {
		t.Fatalf("startup diagnostic did not preserve only the typed reason: %q", reason)
	}
}

func TestFailedStartupStdoutClassifiesWithoutEchoingContent(t *testing.T) {
	for _, tc := range []struct{ raw, want string }{
		{"", "no-handshake"},
		{gvxcontract.BridgeMagic + "private payload", "valid-magic"},
		{"untrusted startup bytes", "unexpected-bytes"},
	} {
		t.Run(tc.want, func(t *testing.T) {
			r, w, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer r.Close()
			defer w.Close()
			if err := r.SetReadDeadline(time.Now().Add(time.Second)); err != nil {
				t.Skip("native pipe does not support read deadlines")
			}
			if _, err := w.WriteString(tc.raw); err != nil {
				t.Fatal(err)
			}
			if err := w.Close(); err != nil {
				t.Fatal(err)
			}
			i := &instance{startupPhase: "authenticate-engine", pipes: &stdio{output: r}}
			if got := failedStartupStdout(i); got != tc.want {
				t.Fatalf("stdout classification = %q, want %q", got, tc.want)
			}
		})
	}
}
