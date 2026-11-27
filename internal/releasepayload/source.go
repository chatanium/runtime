// Package releasepayload is imported only by the static outer executable. The
// worker and helpers are built before these required inputs are generated.
package releasepayload

import (
	"context"
	"embed"
	"io"
	"os"
	"runtime"

	"github.com/thirdscam/chatanium/internal/bundle"
)

// Missing acquired/verified build inputs intentionally fail compilation.
//
//go:embed assets/manifest.json assets/bundle.tar.gz
var assets embed.FS

type embeddedSource struct{}

func Source() bundle.Source                      { return embeddedSource{} }
func (embeddedSource) Manifest() ([]byte, error) { return assets.ReadFile("assets/manifest.json") }
func (embeddedSource) Open() (io.ReadCloser, error) {
	file, err := assets.Open("assets/bundle.tar.gz")
	if err != nil {
		return nil, err
	}
	return file, nil
}

// InspectPortable returns the immutable manifest for this executable's exact
// host target without writing to the host or probing its capabilities.
func InspectPortable() (bundle.PortableManifest, error) {
	raw, err := Source().Manifest()
	if err != nil {
		return bundle.PortableManifest{}, err
	}
	return bundle.VerifyPortableManifest(raw, runtime.GOOS, runtime.GOARCH)
}

// ExtractPortable requires a preapproved, private and empty code-generation
// handle. Publish only on success; discard partially extracted files on error.
func ExtractPortable(ctx context.Context, destination *os.Root) (bundle.PortableManifest, error) {
	return bundle.ExtractPortable(ctx, Source(), destination, runtime.GOOS, runtime.GOARCH)
}

// VerifyPortable rechecks an installed code generation against this executable.
func VerifyPortable(ctx context.Context, destination *os.Root) (bundle.PortableManifest, error) {
	return bundle.VerifyPortableDirectory(ctx, Source(), destination, runtime.GOOS, runtime.GOARCH)
}
