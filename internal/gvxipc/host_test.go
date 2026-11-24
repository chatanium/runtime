package gvxipc

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"net"
	"testing"
	"time"

	"github.com/thirdscam/chatanium/internal/gvxcontract"
)

func TestPortableHostPreparesGuestRoots(t *testing.T) {
	for _, badNonce := range []bool{false, true} {
		name := "bound result"
		if badNonce {
			name = "wrong nonce"
		}
		t.Run(name, func(t *testing.T) {
			binding := gvxcontract.RootBinding{RuntimeInstallationID: "installation", EpochID: "epoch", InstanceID: "instance", IntentID: "intent", Nonce: "nonce"}
			approved := gvxcontract.PortableRootLimits{MaxPIDs: 64, PersistentBytes: 64 << 20, ScratchBytes: 32 << 20, ShmBytes: 1 << 20}
			manifest, err := gvxcontract.NewPortableRootManifest(binding, approved, 1000, 1000, true)
			if err != nil {
				t.Fatal(err)
			}
			init := gvxcontract.BridgeInit{
				Argv: []string{"/opt/module"}, Workdir: "/", UID: 1000, GID: 1000, SocketDir: "/tmp/plugin-dir1", Roots: manifest,
				Env: []string{"FLEXMODULE_PLUGIN=CHATANIUM_FOREVER", "PLUGIN_PROTOCOL_VERSIONS=2", "PLUGIN_MULTIPLEX_GRPC=true", "PLUGIN_CLIENT_CERT=cert", "PLUGIN_UNIX_SOCKET_DIR=/tmp/plugin-dir1", "PLUGIN_UNIX_SOCKET_GROUP=1000"},
			}
			// Minimal DER envelope for framing and guest path validation; TLS
			// authenticates the real certificate after OPEN.
			der := []byte{0x30, 8, 0x30, 0, 0x30, 0, 0x03, 2, 0, 0}
			line := "1|2|unix|/tmp/plugin-dir1/module.sock|grpc|" + base64.RawStdEncoding.EncodeToString(der) + "|true\n"
			a, b := net.Pipe()
			defer a.Close()
			defer b.Close()
			deadline := time.Now().Add(5 * time.Second)
			if err = a.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			if err = b.SetDeadline(deadline); err != nil {
				t.Fatal(err)
			}
			limits := Limits{ControlMessageMaxBytes: MaxControl, LogBufferBytes: 1 << 20}
			host, err := NewCodec(a, a, Host, limits)
			if err != nil {
				t.Fatal(err)
			}
			guest, err := NewCodec(b, b, Guest, limits)
			if err != nil {
				t.Fatal(err)
			}
			guestDone := make(chan error, 1)
			go func() {
				err := func() error {
					// net.Pipe is unbuffered, unlike the two GVX stdio pipes.
					if err := guest.ReadMagic(); err != nil {
						return err
					}
					if err := guest.SendMagic(); err != nil {
						return err
					}
					typ, raw, err := guest.Read()
					if err != nil || typ != Init {
						return errors.New("missing INIT frame")
					}
					var got gvxcontract.BridgeInit
					if err = gvxcontract.DecodeStrict(raw, MaxControl, 16, &got); err != nil {
						return err
					}
					p, err := ValidateInit(got, MaxControl)
					if err != nil {
						return err
					}
					if p.Version != gvxcontract.PortableRootPayloadVersion || p.PortableLimits == nil || *p.PortableLimits != approved || got.Roots.Digest != manifest.Digest {
						return errors.New("portable approved limits not carried by INIT")
					}
					ready := gvxcontract.RootInitResult{Digest: got.Roots.Digest, Nonce: p.Nonce}
					if badNonce {
						ready.Nonce = "stale nonce"
					}
					for _, root := range p.Roots {
						ready.Results = append(ready.Results, gvxcontract.RootStepResult{RootID: root.RootID, Step: 2, Observed: root.Target})
					}
					raw, err = json.Marshal(ready)
					if err != nil {
						return err
					}
					if err = guest.Write(RootsReady, raw); err != nil || badNonce {
						return err
					}
					if typ, _, err := guest.Read(); err != nil || typ != RootsCommit {
						return errors.New("missing durable ROOTS_COMMIT frame")
					}
					return guest.Write(Handshake, []byte(line))
				}()
				guestDone <- err
			}()
			result, err := PrepareHost(host, init)
			if badNonce {
				if !errors.Is(err, ErrInvalidFrame) {
					t.Fatalf("wrong nonce accepted: %v", err)
				}
			} else {
				if err != nil || result.Digest != manifest.Digest || result.Nonce != binding.Nonce {
					t.Fatalf("portable root confirmation: %+v, %v", result, err)
				}
				if err = host.Write(RootsCommit, nil); err != nil {
					t.Fatal(err)
				}
				if got, err := ReadHandshake(host, init.SocketDir); err != nil || string(got) != line {
					t.Fatalf("portable guest handshake: %q, %v", got, err)
				}
			}
			if err = <-guestDone; err != nil {
				t.Fatal(err)
			}
		})
	}
}
