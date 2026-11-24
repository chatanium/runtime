package provision

import (
	"archive/tar"
	"testing"
)

func TestPortableLayerCannotReplaceBridgeMount(t *testing.T) {
	for _, c := range []struct {
		name    string
		kind    byte
		allowed bool
	}{
		{"run", tar.TypeDir, true},
		{"run", tar.TypeSymlink, false},
		{"run", tar.TypeLink, false},
		{".", tar.TypeReg, false},
		{".wh.run", tar.TypeReg, false},
		{"run/.wh.chatanium-bootstrap", tar.TypeReg, false},
		{"run/chatanium-bootstrap", tar.TypeDir, false},
		{"run/chatanium-bootstrap/portable/verified/guest-bridge", tar.TypeReg, false},
		{"run/module.sock", tar.TypeReg, true},
		{"bin/app", tar.TypeReg, true},
	} {
		if allowed := portableLayerPath(c.name, c.kind); allowed != c.allowed {
			t.Errorf("portableLayerPath(%q, %d) = %t, want %t", c.name, c.kind, allowed, c.allowed)
		}
	}
}
