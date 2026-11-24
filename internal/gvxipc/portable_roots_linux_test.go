//go:build linux

package gvxipc

import (
	"testing"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
	"golang.org/x/sys/unix"
)

func TestPortableShmLimitNeverDefaults(t *testing.T) {
	const page = 4096
	const safeFlags = unix.MS_NODEV | unix.MS_NOSUID | unix.MS_NOEXEC
	for _, tc := range []struct {
		approved int64
		bytes    int64
		attrs    gvxcontract.RootAttrs
		flags    uintptr
	}{
		{0, page, gvxcontract.RootAttrs{}, safeFlags | unix.MS_RDONLY},
		{3 * page, 3 * page, gvxcontract.RootAttrs{UID: 123, GID: 456, Mode: 0700}, safeFlags},
	} {
		bytes, attrs, flags, err := portableShmSpec(tc.approved, page, 123, 456)
		if err != nil || bytes != tc.bytes || attrs != tc.attrs || flags != tc.flags {
			t.Fatalf("/dev/shm config for %d: %d bytes, %+v, flags %#x, %v", tc.approved, bytes, attrs, flags, err)
		}
	}
	if _, _, _, err := portableShmSpec(page+1, page, 123, 456); err == nil {
		t.Fatal("unaligned approved size handled as a rounded or default tmpfs")
	}
}
