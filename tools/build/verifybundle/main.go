// Command verifybundle checks generated payload bytes without installation,
// privilege, extraction or execution of any bundled program.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"github.com/thirdscam/chatanium/internal/bundle"
)

type source string

func (s source) Manifest() ([]byte, error) {
	f, err := os.Open(filepath.Join(string(s), "manifest.json"))
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(io.LimitReader(f, bundle.MaxManifestBytes+1))
}

func (s source) Open() (io.ReadCloser, error) {
	return os.Open(filepath.Join(string(s), "bundle.tar.gz"))
}

func main() {
	if len(os.Args) != 3 {
		fmt.Fprintln(os.Stderr, "usage: verifybundle OS/ARCH PAYLOAD_DIRECTORY")
		os.Exit(2)
	}
	osName, arch, ok := strings.Cut(os.Args[1], "/")
	if !ok {
		fmt.Fprintln(os.Stderr, "portable bundle target must be OS/ARCH")
		os.Exit(2)
	}
	m, err := bundle.ValidatePortableArchive(context.Background(), source(os.Args[2]), osName, arch)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("Verified %s bundle %s for %s/%s (%s)\n", m.Format, m.Digest, m.Target.OS, m.Target.Arch, m.Target.Backend)
}
