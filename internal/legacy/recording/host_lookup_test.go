package recording

import (
	"context"
	"errors"
	"io"
	"net/http"
	"strings"
	"testing"
	"time"

	"github.com/bwmarrin/discordgo"
)

type hostRoundTrip func(*http.Request) (*http.Response, error)

func (f hostRoundTrip) RoundTrip(request *http.Request) (*http.Response, error) {
	return f(request)
}

func TestHostLookupBoundsUnknownLengthResponses(t *testing.T) {
	session := &discordgo.Session{Token: "Bot host-fixture", Client: &http.Client{Transport: hostRoundTrip(func(request *http.Request) (*http.Response, error) {
		if request.Header.Get("Authorization") != "Bot host-fixture" || request.Method != http.MethodGet {
			t.Error("host lookup did not use trusted read-only request")
		}
		return &http.Response{StatusCode: http.StatusOK, ContentLength: -1, Header: make(http.Header), Body: io.NopCloser(strings.NewReader(`{"value":"` + strings.Repeat("a", 128) + `"}`))}, nil
	})}}
	var output map[string]string
	if err := readHostJSON(context.Background(), session, "https://host.invalid/fixture", 32, &output); err == nil {
		t.Fatal("oversized unknown-length host response accepted")
	}
}

func TestHostLookupCancellationReachesHTTPRequest(t *testing.T) {
	session := &discordgo.Session{Client: &http.Client{Transport: hostRoundTrip(func(request *http.Request) (*http.Response, error) {
		<-request.Context().Done()
		return nil, request.Context().Err()
	})}}
	ctx, cancel := context.WithTimeout(context.Background(), 100*time.Millisecond)
	defer cancel()
	var output discordgo.Member
	if err := readHostJSON(ctx, session, "https://host.invalid/fixture", 1024, &output); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("lookup did not return its bounded context error: %v", err)
	}
}
