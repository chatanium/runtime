// Command manifest validates the canonical embedded protobuf JSON and emits its
// original bytes, including whitespace, for the OCI image declaration label.
package main

import (
	"fmt"
	"os"

	core "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/protobuf/encoding/protojson"
)

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: manifest canonical-manifest.json")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err == nil {
		err = (protojson.UnmarshalOptions{DiscardUnknown: false}).Unmarshal(data, new(core.ModuleManifest))
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if _, err = os.Stdout.Write(data); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
}
