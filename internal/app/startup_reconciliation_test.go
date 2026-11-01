package app

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"io"
	"testing"

	"github.com/thirdscam/chatanium/internal/host"
)

type startupReconciler struct{ err error }

func (s startupReconciler) Reconcile(context.Context) error { return s.err }

func TestStartupReconciliationAllowsOnlyExplicitPendingResult(t *testing.T) {
	for _, tc := range []struct {
		name    string
		err     error
		pending bool
		failed  bool
	}{
		{"complete", nil, false, false},
		{"pending", &host.Error{Reason: "HOST_RECONCILIATION_PENDING", Message: "unsafe fixture diagnostic"}, true, false},
		{"unresolved operation", &host.Error{Reason: "CREATE_OUTCOME_UNRESOLVED"}, false, true},
		{"incomplete", &host.Error{Reason: "CLEANUP_INCOMPLETE"}, false, true},
		{"enforcement", &host.Error{Reason: "HOST_PREREQUISITE_FAILED"}, false, true},
		{"transport", context.DeadlineExceeded, false, true},
		{"mixed pending", errors.Join(&host.Error{Reason: "HOST_RECONCILIATION_PENDING"}, context.DeadlineExceeded), false, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var output bytes.Buffer
			err := reconcileHost(context.Background(), startupReconciler{tc.err}, &output, 2)
			if (err != nil) != tc.failed {
				t.Fatalf("startup reconciliation failed = %v, want %t", err, tc.failed)
			}
			if !tc.pending {
				if output.Len() != 0 {
					t.Fatal("nonpending result emitted a pending observation")
				}
				return
			}
			var out observation
			if err := json.Unmarshal(output.Bytes(), &out); err != nil {
				t.Fatal(err)
			}
			if out.Phase != "HOST_RECONCILIATION_PENDING" || out.Modules != 2 || bytes.Contains(output.Bytes(), []byte("unsafe fixture diagnostic")) {
				t.Fatal("pending outcome missing or raw error text exposed")
			}
		})
	}
}

type failedReconciliationWriter struct{}

func (failedReconciliationWriter) Write([]byte) (int, error) { return 0, io.ErrClosedPipe }

func TestStartupReconciliationCannotSilentlyDiscardPendingObservation(t *testing.T) {
	err := reconcileHost(context.Background(), startupReconciler{&host.Error{Reason: "HOST_RECONCILIATION_PENDING"}}, failedReconciliationWriter{}, 1)
	if err == nil || errors.Is(err, io.ErrClosedPipe) {
		t.Fatal("failed pending observation must fail startup without raw output diagnostics")
	}
}
