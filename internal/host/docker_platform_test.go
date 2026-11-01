package host

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/client"
)

func TestDockerPreflightRequiresApprovedCPUPhasePolicies(t *testing.T) {
	const isolationMismatch = "registered runsc isolation flags mismatch"
	const pinRequired = "absolute executable and SHA256 pin required"
	for _, driver := range []string{"systemd", "cgroupfs"} {
		for _, tc := range []struct {
			name, creation, lifecycle, extra, want string
		}{
			{"approved", "1x", "1x", "", pinRequired},
			{"missing creation", "", "1x", "", isolationMismatch},
			{"uncapped creation", "uncapped", "1x", "", isolationMismatch},
			{"boosted creation", "4x", "1x", "", isolationMismatch},
			{"missing lifecycle", "1x", "", "", isolationMismatch},
			{"boosted lifecycle", "1x", "4x", "", isolationMismatch},
			{"uncapped lifecycle", "1x", "uncapped", "", isolationMismatch},
			{"both defaults", "", "", "", isolationMismatch},
			{"creation override", "1x", "1x", "--sandbox-creation-cpu-policy=uncapped", "unapproved extra runsc arguments"},
			{"lifecycle override", "1x", "1x", "--sandbox-lifecycle-cpu-policy=4x", "unapproved extra runsc arguments"},
		} {
			t.Run(driver+"/"+tc.name, func(t *testing.T) {
				args := []string{"--platform=systrap", "--host-uds=create", "--file-access-mounts=shared", "--overlay2=root:self"}
				if tc.creation != "" {
					args = append(args, "--sandbox-creation-cpu-policy="+tc.creation)
				}
				if tc.lifecycle != "" {
					args = append(args, "--sandbox-lifecycle-cpu-policy="+tc.lifecycle)
				}
				if driver == "systemd" {
					args = append(args, "--systemd-cgroup")
				}
				if tc.extra != "" {
					args = append(args, tc.extra)
				}
				requests := 0
				cli, err := client.New(client.WithAPIVersion("1.54"), client.WithHTTPClient(&http.Client{Transport: networkTestTransport(func(r *http.Request) (*http.Response, error) {
					requests++
					if r.Method != http.MethodGet || r.URL.Path != "/v1.54/info" {
						return nil, fmt.Errorf("unexpected Docker request: %s %s", r.Method, r.URL.Path)
					}
					data, err := json.Marshal(map[string]any{
						"ServerVersion": "29.5.3", "OSType": "linux", "CgroupVersion": "2", "CgroupDriver": driver,
						"MemoryLimit": true, "SwapLimit": true, "PidsLimit": true, "CpuCfsQuota": true,
						"Runtimes": map[string]any{"approved-runsc": map[string]any{"path": "/pinned/runsc", "runtimeArgs": args}},
					})
					if err != nil {
						return nil, err
					}
					return &http.Response{StatusCode: http.StatusOK, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(string(data))), Request: r}, nil
				})}))
				if err != nil {
					t.Fatal(err)
				}
				t.Cleanup(func() { cli.Close() })
				// An intentionally absent digest makes the next independent prerequisite
				// fail before any executable or host-network access. The approved case
				// must reach that check; every unapproved daemon flag must fail earlier.
				platform := &DockerPlatform{docker: cli, cfg: DockerConfig{EngineVersion: "29.5.3", RuntimeName: "approved-runsc", RunscPath: "/pinned/runsc", APIDeadline: time.Second}}
				err = platform.Preflight(context.Background())
				var failure *Error
				if !errors.As(err, &failure) || failure.Reason != "HOST_PREREQUISITE_FAILED" || failure.Message != tc.want {
					t.Fatalf("Preflight() = %v, want HOST_PREREQUISITE_FAILED: %s", err, tc.want)
				}
				if requests != 1 {
					t.Fatalf("Docker requests = %d, want one actual runtime-info check", requests)
				}
			})
		}
	}
}
