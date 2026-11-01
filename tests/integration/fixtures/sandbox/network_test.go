package main

import (
	"context"
	"encoding/binary"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	wire "github.com/thirdscam/chatanium/proto/core-v2"
	core "github.com/thirdscam/chatanium/shared/core-v2"
	"golang.org/x/net/dns/dnsmessage"
)

func TestNetworkScenarioCannotGrantItselfPublicEgress(t *testing.T) {
	c := probeConfig{Scenario: &scenarioConfig{Kind: "network", Network: &networkConfig{ExpectedEgress: "PUBLIC_INTERNET"}}}
	actual := &wire.InitContext{Grants: &wire.Grants{EgressPolicy: wire.EgressPolicy_EGRESS_POLICY_NONE}}
	if err := validateFixtureGrants(c, actual); err == nil {
		t.Fatal("configuration granted public egress without actual approval")
	}
	if actual.Grants.EgressPolicy != wire.EgressPolicy_EGRESS_POLICY_NONE || len(actual.Grants.CoreCapabilities) != 0 {
		t.Fatal("grant validation mutated actual grants")
	}
	actual.Grants.EgressPolicy = wire.EgressPolicy_EGRESS_POLICY_PUBLIC_INTERNET
	if err := validateFixtureGrants(c, actual); err == nil {
		t.Fatal("PUBLIC policy without its actual capability accepted")
	}
	actual.Grants.CoreCapabilities = []*wire.CapabilityGrant{{Name: core.CapabilityPublicEgress}}
	if err := validateFixtureGrants(c, actual); err == nil {
		t.Fatal("unscoped public capability accepted")
	}
	actual.Grants.CoreCapabilities[0].ResourceScopes = []*wire.ResourceScope{{SelectorKind: &wire.ResourceScope_Selector{Selector: &wire.ResourceSelector{}}}}
	if err := validateFixtureGrants(c, actual); err != nil {
		t.Fatalf("actual scoped PUBLIC grant rejected: %v", err)
	}
	if err := validateFixtureGrants(probeConfig{}, actual); err == nil {
		t.Fatal("PUBLIC execution accepted without explicit network opt-in")
	}
	actual.Grants.EgressPolicy = wire.EgressPolicy_EGRESS_POLICY_NONE
	actual.Grants.CoreCapabilities = nil
	if err := validateFixtureGrants(probeConfig{}, actual); err != nil {
		t.Fatalf("unapproved optional egress broke NONE execution: %v", err)
	}
}

func TestNetworkScenarioRejectsUnboundedOrAmbiguousTargets(t *testing.T) {
	base := func() networkConfig {
		return networkConfig{ExpectedEgress: "NONE", OperationTimeoutMS: 100, TCP: []tcpTarget{{Address: "127.0.0.1:1234", Expect: "deny"}}}
	}
	cases := []func(*networkConfig){
		func(c *networkConfig) { c.ExpectedEgress = "ANY" },
		func(c *networkConfig) { c.OperationTimeoutMS = 0 },
		func(c *networkConfig) { c.OperationTimeoutMS = 10001 },
		func(c *networkConfig) { c.TCP = nil },
		func(c *networkConfig) { c.TCP[0].Address = "example.test:1234" },
		func(c *networkConfig) { c.TCP[0].Address = "127.0.0.1:0" },
		func(c *networkConfig) { c.TCP[0].Expect = "pass" },
		func(c *networkConfig) { c.TCP = make([]tcpTarget, 17) },
		func(c *networkConfig) {
			c.DNS = []dnsQuery{{Resolver: "resolver.test:53", Transport: "udp", Name: "fixture.test", Type: "A", Expect: "response"}}
		},
		func(c *networkConfig) {
			c.DNS = []dnsQuery{{Resolver: "127.0.0.1:53", Transport: "udp", Name: strings.Repeat("a", 64) + ".test", Type: "A", Expect: "response"}}
		},
		func(c *networkConfig) { c.DNS = make([]dnsQuery, 9) },
		func(c *networkConfig) {
			c.HTTP = []httpTarget{{URL: "http://credential@127.0.0.1/", MaxRedirects: 1, Expect: "response"}}
		},
		func(c *networkConfig) {
			c.HTTP = []httpTarget{{URL: "http://127.0.0.1/", MaxRedirects: 4, Expect: "response"}}
		},
		func(c *networkConfig) { c.HTTP = make([]httpTarget, 3) },
		func(c *networkConfig) {
			c.Fresh = []freshResolution{{Resolver: "127.0.0.1:53", Transport: "udp", Name: "fixture.test", Type: "A", Port: 80, Rounds: 4, MaxAddresses: 1, Expect: "connect"}}
		},
		func(c *networkConfig) { c.Fresh = make([]freshResolution, 3) },
	}
	for i, mutate := range cases {
		c := base()
		mutate(&c)
		if err := validateNetwork(&c); err == nil {
			t.Fatalf("invalid bounded network case %d accepted", i)
		}
	}
}

// A real local responder verifies DNS transport/response boundaries, not any
// production firewall. Its address is supplied explicitly just like host probes.
func startProbeDNSResponder(t *testing.T, transport string, mismatchID bool) (string, <-chan error, func()) {
	t.Helper()
	done := make(chan error, 1)
	answer := func(packet []byte) ([]byte, error) {
		var query dnsmessage.Message
		if err := query.Unpack(packet); err != nil {
			return nil, err
		}
		if len(query.Questions) != 1 {
			return nil, errors.New("unexpected probe question count")
		}
		query.Response = true
		if mismatchID {
			query.ID++
		}
		for i := range 5 {
			query.Answers = append(query.Answers, dnsmessage.Resource{Header: dnsmessage.ResourceHeader{Name: query.Questions[0].Name, Type: dnsmessage.TypeA, Class: dnsmessage.ClassINET}, Body: &dnsmessage.AResource{A: [4]byte{127, 0, 0, byte(42 + i)}}})
		}
		return query.Pack()
	}
	if transport == "udp" {
		conn, err := net.ListenPacket("udp4", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		go func() {
			_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
			packet := make([]byte, 512)
			n, peer, err := conn.ReadFrom(packet)
			if err == nil {
				var response []byte
				response, err = answer(packet[:n])
				if err == nil {
					_, err = conn.WriteTo(response, peer)
				}
			}
			done <- err
		}()
		return conn.LocalAddr().String(), done, func() { _ = conn.Close() }
	}
	listener, err := net.Listen("tcp4", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() {
		_ = listener.(*net.TCPListener).SetDeadline(time.Now().Add(2 * time.Second))
		conn, err := listener.Accept()
		if err != nil {
			done <- err
			return
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		var prefix [2]byte
		_, err = io.ReadFull(conn, prefix[:])
		n := int(binary.BigEndian.Uint16(prefix[:]))
		if err == nil && n > 512 {
			err = errors.New("oversized test query")
		}
		if err == nil {
			packet := make([]byte, n)
			_, err = io.ReadFull(conn, packet)
			if err == nil {
				var response []byte
				response, err = answer(packet)
				if err == nil {
					framed := make([]byte, 2+len(response))
					binary.BigEndian.PutUint16(framed, uint16(len(response)))
					copy(framed[2:], response)
					_, err = conn.Write(framed)
				}
			}
		}
		done <- err
	}()
	return listener.Addr().String(), done, func() { _ = listener.Close() }
}

func TestExplicitDNSUsesRequestedTransportAndBoundsSelectedAddresses(t *testing.T) {
	for _, transport := range []string{"udp", "tcp"} {
		t.Run(transport, func(t *testing.T) {
			address, done, closeResponder := startProbeDNSResponder(t, transport, false)
			defer closeResponder()
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
			defer cancel()
			result, err := queryDNS(ctx, dnsQuery{Resolver: address, Transport: transport, Name: "fixture.test", Type: "A", Expect: "response"}, 2)
			if err != nil || len(result.addresses) != 2 || result.addresses[0] != "127.0.0.42" || result.data["answer_records"] != 5 || result.data["received_response"] != true {
				t.Fatalf("real DNS observation did not match bounded response: result=%+v err=%v", result, err)
			}
			select {
			case err := <-done:
				if err != nil {
					t.Fatal(err)
				}
			case <-ctx.Done():
				t.Fatal("test responder did not terminate")
			}
		})
	}
}

func TestDNSMismatchedResponseCannotBecomeAnObservationOfSuccess(t *testing.T) {
	address, done, closeResponder := startProbeDNSResponder(t, "udp", true)
	defer closeResponder()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	result, err := queryDNS(ctx, dnsQuery{Resolver: address, Transport: "udp", Name: "fixture.test", Type: "A", Expect: "response"}, 4)
	if err == nil || len(result.addresses) != 0 || result.data["received_response"] != false {
		t.Fatal("mismatched DNS response became a successful observation")
	}
	select {
	case <-done:
	case <-ctx.Done():
		t.Fatal("test responder did not terminate")
	}
}

func TestHTTPFollowsRealRedirectWithoutForwardingOrRecordingSecrets(t *testing.T) {
	var reached, leaked atomic.Bool
	destination := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached.Store(true)
		leaked.Store(r.Header.Get("Authorization") != "" || r.Header.Get("Cookie") != "")
		w.Header().Set("X-Private-Test", "header-private-marker")
		_, _ = io.WriteString(w, "body-private-marker")
	}))
	defer destination.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Set-Cookie", "session=cookie-private-marker")
		http.Redirect(w, r, destination.URL+"/path-private-marker?key=query-private-marker", http.StatusFound)
	}))
	defer origin.Close()
	p, err := newProbeSession(t.TempDir(), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	report := p.file.Name()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	httpObservation(ctx, 500, httpTarget{URL: origin.URL, MaxRedirects: 1, Expect: "response"}, 0, p)
	p.close()
	if !reached.Load() || leaked.Load() {
		t.Fatal("real redirect was not followed or forwarded credential state")
	}
	data, err := os.ReadFile(report)
	if err != nil {
		t.Fatal(err)
	}
	for _, marker := range []string{"path-private-marker", "query-private-marker", "header-private-marker", "body-private-marker", "cookie-private-marker"} {
		if strings.Contains(string(data), marker) {
			t.Fatal("private HTTP content was serialized")
		}
	}
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	statuses := make([]int, 0, 2)
	for {
		var v observation
		if err := decoder.Decode(&v); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		if status, ok := v.Data["status"].(float64); ok {
			statuses = append(statuses, int(status))
		}
	}
	if len(statuses) != 2 || statuses[0] != 302 || statuses[1] != 200 {
		t.Fatalf("real redirect response observations missing: %v", statuses)
	}
}
