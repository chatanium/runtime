//go:build linux

package host

import (
	"errors"
	"strconv"
	"testing"
)

func TestProjectLimitsUseFilesystemBlockGranularity(t *testing.T) {
	for _, blockBytes := range []int64{512, 4096, 65536} {
		t.Run(strconv.FormatInt(blockBytes, 10), func(t *testing.T) {
			q := quotaFS{blockBytes: blockBytes}
			got, err := q.projectLimits(1, 1<<30, 65536)
			if err != nil {
				t.Fatal(err)
			}
			if got.BlockHard != 2097152 || got.BlockSoft != 2097152 || got.InodeHard != 65536 || got.InodeSoft != 65536 {
				t.Fatalf("approved ordinary limits changed: %+v", got)
			}
			if got.RTBlockHard != uint64(blockBytes/512) || got.RTBlockSoft != uint64(blockBytes/512) {
				t.Fatalf("realtime guard is not exactly one filesystem block: %+v", got)
			}
		})
	}
}

func TestProjectLimitsRejectUpwardRounding(t *testing.T) {
	q := quotaFS{blockBytes: 4096}
	for _, bytes := range []int64{512, 4095, 4097, 4608, (1 << 30) + 512} {
		_, err := q.projectLimits(1, bytes, 65536)
		var typed *Error
		if !errors.As(err, &typed) || typed.Reason != "INVALID_CONFIGURATION" {
			t.Fatalf("unaligned approved ceiling %d must fail without rounding: %v", bytes, err)
		}
	}
}

func TestProjectLimitsRequireValidatedGeometry(t *testing.T) {
	for _, blockBytes := range []int64{0, 1, 511, 513} {
		q := quotaFS{blockBytes: blockBytes}
		_, err := q.projectLimits(1, 1<<30, 65536)
		var typed *Error
		if !errors.As(err, &typed) || typed.Reason != "HOST_PREREQUISITE_FAILED" {
			t.Fatalf("invalid filesystem geometry %d accepted: %v", blockBytes, err)
		}
	}
}
