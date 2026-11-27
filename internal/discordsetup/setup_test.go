package discordsetup

import (
	"context"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"
)

const fixtureToken = "fixture.only.not.a.real.token"

func fixtureAPI(t *testing.T, handler http.HandlerFunc) api {
	t.Helper()
	server := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodGet || r.Host != "discord.com" || r.TLS == nil || r.Header.Get("Authorization") != "Bot "+fixtureToken || r.Header.Get("Proxy-Authorization") != "" {
			t.Error("expected a direct authenticated Discord HTTPS GET")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		handler(w, r)
	}))
	t.Cleanup(server.Close)
	client := newHTTPClient()
	transport := client.Transport.(*http.Transport)
	transport.TLSClientConfig.RootCAs = x509.NewCertPool()
	transport.TLSClientConfig.RootCAs.AddCert(server.Certificate())
	transport.TLSClientConfig.ServerName = server.Listener.Addr().(*net.TCPAddr).IP.String()
	dial := transport.DialContext
	transport.DialContext = func(ctx context.Context, network, addr string) (net.Conn, error) {
		if addr != "discord.com:443" {
			t.Errorf("unexpected dial address %q", addr)
			return nil, fmt.Errorf("unexpected destination")
		}
		return dial(ctx, network, server.Listener.Addr().String())
	}
	t.Cleanup(client.CloseIdleConnections)
	return api{client: client}
}

func TestLookupIdentity(t *testing.T) {
	t.Setenv("HTTPS_PROXY", "http://unused:password@proxy.invalid:8080")
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v10/applications/@me":
			io.WriteString(w, `{"id":"101","name":"Application","bot":{"id":"202"},"flags":1,"flags_new":"1099511627776"}`)
		case "/api/v10/users/@me":
			io.WriteString(w, `{"id":"202","bot":true,"username":" Chat\u001b\u202e\nBot "}`)
		default:
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
		}
	})
	got, err := a.lookupIdentity(context.Background(), fixtureToken)
	if err != nil || got.ApplicationID != "101" || got.BotUserID != "202" || got.Name != "Chat Bot" || got.Flags == nil || *got.Flags != 1<<40 {
		t.Fatalf("identity = %+v, %v", got, err)
	}
}

func TestLookupIdentityRejectsWrongUser(t *testing.T) {
	for _, user := range []string{`{"id":"202","bot":false}`, `{"id":"303","bot":true}`} {
		a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
			switch r.URL.Path {
			case "/api/v10/applications/@me":
				io.WriteString(w, `{"id":"101","bot":{"id":"202"}}`)
			case "/api/v10/users/@me":
				io.WriteString(w, user)
			default:
				w.WriteHeader(http.StatusNotFound)
			}
		})
		if got, err := a.lookupIdentity(context.Background(), fixtureToken); err == nil || got != (Identity{}) {
			t.Fatalf("expected no identity for %s, got %+v, %v", user, got, err)
		}
	}
}

func TestLookupDoesNotFollowRedirectsOrEchoCredentials(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/api/v10/applications/@me":
			w.Header().Set("Location", "/unexpected?credential="+fixtureToken)
			w.WriteHeader(http.StatusFound)
			io.WriteString(w, fixtureToken)
		case "/api/v10/users/@me/guilds":
			w.WriteHeader(http.StatusUnauthorized)
			io.WriteString(w, fixtureToken)
		default:
			t.Error("followed a redirect")
		}
	})
	_, identityErr := a.lookupIdentity(context.Background(), fixtureToken)
	_, guildErr := a.listGuilds(context.Background(), fixtureToken)
	if identityErr == nil || !strings.Contains(identityErr.Error(), "302") || strings.Contains(identityErr.Error(), fixtureToken) {
		t.Fatalf("unsafe or missing redirect error: %v", identityErr)
	}
	if guildErr == nil || !strings.Contains(guildErr.Error(), "401") || strings.Contains(guildErr.Error(), fixtureToken) {
		t.Fatalf("unsafe or missing authentication error: %v", guildErr)
	}
}

func TestInvalidTokenDoesNotReachDiscord(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		t.Error("invalid token reached Discord")
		w.WriteHeader(http.StatusInternalServerError)
	})
	for _, token := range []string{"", "Bot " + fixtureToken, fixtureToken + "\r\nX-Other: value"} {
		_, err := a.lookupIdentity(context.Background(), token)
		if err != errInvalidToken {
			t.Fatalf("expected a local token error, got %v", err)
		}
	}
}

func TestListGuildsPaginates(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v10/users/@me/guilds" || r.URL.Query().Get("limit") != "200" {
			t.Error("expected the paginated current-user guild endpoint")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		switch r.URL.Query().Get("after") {
		case "":
			guilds := make([]Guild, 200)
			for i := range guilds {
				guilds[i] = Guild{ID: strconv.Itoa(i + 100), Name: "Test guild"}
			}
			json.NewEncoder(w).Encode(guilds)
		case "299":
			fmt.Fprintf(w, `[{"id":"300","name":%q}]`, fixtureToken)
		default:
			t.Error("unexpected pagination cursor")
			w.WriteHeader(http.StatusBadRequest)
		}
	})
	got, err := a.listGuilds(context.Background(), fixtureToken)
	if err != nil || len(got) != 201 || got[0].ID != "100" || got[200] != (Guild{ID: "300", Name: "300"}) {
		t.Fatalf("guild pagination returned %d guilds, %v", len(got), err)
	}
}

func TestListGuildsRejectsRepeatedPage(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		guilds := make([]Guild, 200)
		for i := range guilds {
			guilds[i] = Guild{ID: strconv.Itoa(i + 100)}
		}
		json.NewEncoder(w).Encode(guilds)
	})
	if got, err := a.listGuilds(context.Background(), fixtureToken); err == nil || got != nil {
		t.Fatalf("repeated page returned %d guilds, %v", len(got), err)
	}
}

func TestListGuildsCapsOutputWithoutReturningPartialResults(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		after, _ := strconv.Atoi(r.URL.Query().Get("after"))
		if after > maxGuilds {
			t.Error("requested another page after exceeding the guild limit")
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		guilds := make([]Guild, guildPageSize)
		for i := range guilds {
			guilds[i] = Guild{ID: strconv.Itoa(after + i + 1)}
		}
		json.NewEncoder(w).Encode(guilds)
	})
	got, err := a.listGuilds(context.Background(), fixtureToken)
	if err == nil || !strings.Contains(err.Error(), "limited") || got != nil {
		t.Fatalf("over-limit discovery returned %d guilds, %v", len(got), err)
	}
}

func TestListChannelsBindsExactGuildAndFiltersTypes(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v10/guilds/101/channels" {
			t.Errorf("unexpected request %s", r.URL.Path)
			w.WriteHeader(http.StatusNotFound)
			return
		}
		io.WriteString(w, `[
			{"id":"201","guild_id":"101","type":0,"name":"text"},
			{"id":"202","type":2,"name":"voice"},
			{"id":"203","type":4,"name":"category"},
			{"id":"204","type":5,"name":"announcements"},
			{"id":"205","type":13,"name":"stage"},
			{"id":"206","type":15,"name":"forum"},
			{"id":"207","type":16,"name":"media"}
		]`)
	})
	got, err := a.listChannels(context.Background(), fixtureToken, "101")
	want := []Channel{
		{ID: "201", GuildID: "101", Type: 0, Name: "text"},
		{ID: "202", GuildID: "101", Type: 2, Name: "voice"},
		{ID: "204", GuildID: "101", Type: 5, Name: "announcements"},
		{ID: "205", GuildID: "101", Type: 13, Name: "stage"},
	}
	if err != nil || len(got) != len(want) {
		t.Fatalf("channels = %+v, %v", got, err)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("channel %d = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestListChannelsRejectsMismatchedGuildAndInvalidPath(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/api/v10/guilds/101/channels" {
			t.Errorf("invalid guild reached Discord: %s", r.URL.Path)
		}
		io.WriteString(w, `[{"id":"201","guild_id":"102","type":0,"name":"wrong guild"}]`)
	})
	for _, id := range []string{"101", "101/../../users/@me", "0101", "18446744073709551616"} {
		if got, err := a.listChannels(context.Background(), fixtureToken, id); err == nil || got != nil {
			t.Fatalf("channels for %q = %+v, %v", id, got, err)
		}
	}
}

func TestListChannelsBoundsResponse(t *testing.T) {
	a := fixtureAPI(t, func(w http.ResponseWriter, _ *http.Request) {
		io.WriteString(w, `[]`+strings.Repeat(" ", maxBodyBytes))
	})
	if got, err := a.listChannels(context.Background(), fixtureToken, "101"); err == nil || got != nil {
		t.Fatalf("oversized response returned %d channels, %v", len(got), err)
	}
}
