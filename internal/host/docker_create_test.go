package host

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/moby/moby/api/types/container"
	"github.com/moby/moby/client"
)

type interruptedCreateBody struct {
	data string
	err  error
}

func (body *interruptedCreateBody) Read(buffer []byte) (int, error) {
	if body.data != "" {
		n := copy(buffer, body.data)
		body.data = body.data[n:]
		return n, nil
	}
	return 0, body.err
}
func (*interruptedCreateBody) Close() error { return nil }

func TestDockerCreateOnlyCompleteNegativeReceiptsResolveSubmission(t *testing.T) {
	for _, kind := range []CreateKind{CreateContainer, CreateNetwork} {
		for _, tc := range []struct {
			name     string
			status   int
			body     string
			readErr  error
			callErr  error
			mismatch bool
			rejected bool
		}{
			{"disk full", 500, `{"message":"mkdir overlay2/init: no space left on device"}`, nil, nil, false, true},
			{"invalid config", 400, `{"message":"invalid configuration"}`, nil, nil, false, true},
			{"missing image", 404, `{"message":"not found"}`, nil, nil, false, true},
			{"name conflict", 409, `{"message":"already exists"}`, nil, nil, false, true},
			{"truncated", 500, `{"message":"rejected"}`, io.ErrUnexpectedEOF, nil, false, false},
			{"body deadline", 500, `{"message":"rejected"}`, context.DeadlineExceeded, nil, false, false},
			{"malformed", 500, `{"message":`, nil, nil, false, false},
			{"empty message", 500, `{"message":""}`, nil, nil, false, false},
			{"success body", 500, `{"Id":"created-object"}`, nil, nil, false, false},
			{"trailing data", 500, `{"message":"rejected"} {}`, nil, nil, false, false},
			{"oversized", 500, `{"message":"` + strings.Repeat("x", 1<<20) + `"}`, nil, nil, false, false},
			{"gateway", 504, `{"message":"upstream timed out"}`, nil, nil, false, false},
			{"unknown status", 503, `{"message":"unavailable"}`, nil, nil, false, false},
			{"success decode error", 201, `{`, nil, nil, false, false},
			{"transport deadline", 0, "", nil, context.DeadlineExceeded, false, false},
			{"unrelated response", 500, `{"message":"rejected"}`, nil, nil, true, false},
		} {
			t.Run(string(kind)+"/"+tc.name, func(t *testing.T) {
				f := newCreateStateFixture(t, EgressNone)
				o := f.lease.Ownership
				identity := containerName(o)
				if kind == CreateNetwork {
					identity += "-net"
				}
				ctx := context.Background()
				if err := f.journal.SubmitCreate(ctx, o, kind, identity); err != nil {
					t.Fatal(err)
				}
				cli, err := client.New(client.WithAPIVersion("1.54"), client.WithHTTPClient(&http.Client{Transport: &createReceiptTransport{base: networkTestTransport(func(request *http.Request) (*http.Response, error) {
					if tc.callErr != nil {
						return nil, tc.callErr
					}
					if request.Method == http.MethodGet {
						return &http.Response{StatusCode: 404, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(`{"message":"No such container"}`)), Request: request}, nil
					}
					if tc.mismatch {
						copy := request.Clone(request.Context())
						copy.URL.Path = "/v1.54/unrelated/create"
						request = copy
					}
					var body io.ReadCloser = io.NopCloser(strings.NewReader(tc.body))
					if tc.readErr != nil {
						body = &interruptedCreateBody{data: tc.body, err: tc.readErr}
					}
					return &http.Response{StatusCode: tc.status, Header: http.Header{"Content-Type": {"application/json"}}, Body: body, Request: request}, nil
				})}}))
				if err != nil {
					t.Fatal(err)
				}
				defer cli.Close()
				request, receipt := createRequest(ctx, kind, identity)
				if kind == CreateContainer {
					_, err = cli.ContainerCreate(request, client.ContainerCreateOptions{Name: identity, Config: &container.Config{Image: "test-image"}})
				} else {
					_, err = cli.NetworkCreate(request, identity, client.NetworkCreateOptions{Driver: "bridge"})
				}
				if err == nil {
					t.Fatal("negative create unexpectedly succeeded")
				}
				cause := err
				if err = recordCreateRejection(cause, receipt, f.journal, o, time.Second); !errors.Is(err, cause) {
					t.Fatal("original create failure was suppressed")
				}
				f.reopen(t)
				record, found, err := f.journal.LookupCreate(ctx, o, kind)
				if err != nil || !found {
					t.Fatalf("durable receipt missing: %+v %t %v", record, found, err)
				}
				want := CreateSubmitted
				if tc.rejected {
					want = CreateRejected
				}
				if record.State != want || record.ObjectID != "" || (record.Rejection != "") != tc.rejected {
					t.Fatalf("receipt state %+v, want %s without fake object ID", record, want)
				}
				if strings.Contains(record.Rejection, "no space left") {
					t.Fatal("raw daemon diagnostics persisted in rejection receipt")
				}
				if err := f.journal.SubmitCreate(ctx, o, kind, identity); !errors.Is(err, ErrCreateAlreadySubmitted) {
					t.Fatalf("resolved or uncertain create was retried: %v", err)
				}
				resolved := requireCreateResolved(ctx, f.journal, o, kind, identity)
				if tc.rejected && resolved != nil || !tc.rejected && !errors.Is(resolved, ErrCreateUnresolved) {
					t.Fatalf("wrong cleanup fence for %s: %v", want, resolved)
				}
				if kind == CreateContainer && tc.callErr == nil && !tc.mismatch {
					platform := &DockerPlatform{docker: cli, creates: f.journal, cfg: DockerConfig{TerminationDeadline: time.Second}}
					err = platform.Reconcile(ctx, o)
					if tc.rejected && err != nil || !tc.rejected && !errors.Is(err, ErrCreateUnresolved) {
						t.Fatalf("platform cleanup ignored completed receipt: %v", err)
					}
				}
				if tc.rejected {
					next := f.lease.Spec
					next.InstanceID = strings.Repeat("d", 32)
					if _, err := f.journal.allocate(ctx, o.EpochID, next, SupervisorConfig{StorageRoot: f.directory, IPCRoot: f.directory, ManagementDirectory: f.directory}); err == nil {
						t.Fatal("rejection receipt released installation before physical cleanup")
					}
					// Physical cleanup remains the platform/storage caller's duty.
					if err := f.journal.cleanup(ctx, o.InstanceID, true, nil); err != nil {
						t.Fatal(err)
					}
					if _, err := f.journal.allocate(ctx, o.EpochID, next, SupervisorConfig{StorageRoot: f.directory, IPCRoot: f.directory, ManagementDirectory: f.directory}); err != nil {
						t.Fatalf("same installation not reusable after proved rejection and cleanup: %v", err)
					}
				}
			})
		}
	}
}

func TestRejectedCreateRetainsOwnershipUntilExactObjectCleanup(t *testing.T) {
	for _, foreign := range []bool{false, true} {
		t.Run(fmt.Sprintf("foreign-%t", foreign), func(t *testing.T) {
			f := newCreateStateFixture(t, EgressNone)
			o := f.lease.Ownership
			ctx := context.Background()
			identity := containerName(o)
			if err := f.journal.SubmitCreate(ctx, o, CreateContainer, identity); err != nil {
				t.Fatal(err)
			}
			if err := f.journal.RejectCreate(ctx, o, CreateContainer, identity, "verified completed rejection"); err != nil {
				t.Fatal(err)
			}
			removed := false
			cli, err := client.New(client.WithAPIVersion("1.54"), client.WithHTTPClient(&http.Client{Transport: networkTestTransport(func(request *http.Request) (*http.Response, error) {
				status, body := 200, `{"Id":"leftover-object","Config":{"Labels":{`
				for key, value := range ownershipLabels(o) {
					if foreign {
						value = "foreign"
					}
					body += fmt.Sprintf("%q:%q,", key, value)
				}
				body = strings.TrimSuffix(body, ",") + `}},"State":{"Running":false}}`
				if request.Method == http.MethodDelete {
					removed = true
					status, body = 204, ""
				} else if removed {
					status, body = 404, `{"message":"not found"}`
				}
				return &http.Response{StatusCode: status, Header: http.Header{"Content-Type": {"application/json"}}, Body: io.NopCloser(strings.NewReader(body)), Request: request}, nil
			})}))
			if err != nil {
				t.Fatal(err)
			}
			defer cli.Close()
			platform := &DockerPlatform{docker: cli, creates: f.journal, cfg: DockerConfig{TerminationDeadline: time.Second}}
			err = platform.Reconcile(ctx, o)
			if foreign {
				if err == nil || removed {
					t.Fatal("completed negative response authorized unrelated object deletion")
				}
			} else if err != nil || !removed {
				t.Fatalf("owned rollback leftover was not safely reclaimed: %t %v", removed, err)
			}
		})
	}
}
