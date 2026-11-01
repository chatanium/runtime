package Log

import (
	"io"
	"os"
	"strings"
	"testing"
)

func TestInitReservesStdoutAndAllowsUnavailableDiskLogs(t *testing.T) {
	for _, tc := range []struct {
		name        string
		mode        string
		blockedDisk bool
	}{
		{name: "production", mode: "production"},
		{name: "development", mode: "development"},
		{name: "unavailable-disk", mode: "production", blockedDisk: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Chdir(t.TempDir())
			t.Setenv("LOG_MODE", tc.mode)
			if tc.blockedDisk {
				if err := os.WriteFile("logs", []byte("not a directory"), 0600); err != nil {
					t.Fatal(err)
				}
			}
			stdoutReader, stdoutWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stdoutReader.Close()
			defer stdoutWriter.Close()
			stderrReader, stderrWriter, err := os.Pipe()
			if err != nil {
				t.Fatal(err)
			}
			defer stderrReader.Close()
			defer stderrWriter.Close()
			oldOut, oldErr := os.Stdout, os.Stderr
			oldVerbose, oldInfo, oldWarn, oldError := Verbose, Info, Warn, Error
			os.Stdout, os.Stderr = stdoutWriter, stderrWriter
			defer func() {
				os.Stdout, os.Stderr = oldOut, oldErr
				Verbose, Info, Warn, Error = oldVerbose, oldInfo, oldWarn, oldError
			}()
			closeLog := Init()
			Info.Println("chatanium-host-identity")
			closeLog()
			stdoutWriter.Close()
			stderrWriter.Close()
			stdout, err := io.ReadAll(stdoutReader)
			if err != nil {
				t.Fatal(err)
			}
			stderr, err := io.ReadAll(stderrReader)
			if err != nil {
				t.Fatal(err)
			}
			if len(stdout) != 0 {
				t.Fatalf("human logs contaminated runtime stdout: %q", stdout)
			}
			if !strings.Contains(string(stderr), "chatanium-host-identity") {
				t.Fatalf("host identity missing from stderr: %q", stderr)
			}
			if tc.blockedDisk && !strings.Contains(string(stderr), "Host disk logs unavailable") {
				t.Fatalf("disk logging failure was not explained: %q", stderr)
			}
		})
	}
}
