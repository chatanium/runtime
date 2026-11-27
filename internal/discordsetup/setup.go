// Package discordsetup makes host-only Discord REST calls for bot setup and ACL discovery.
package discordsetup

import (
	"context"
	"crypto/tls"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"strconv"
	"strings"
	"time"
	"unicode"
)

const (
	baseURL      = "https://discord.com/api/v10"
	maxBodyBytes = 2 << 20
	maxNameRunes = 100
)

var (
	errInvalidToken    = errors.New("enter a Discord bot token without spaces or a Bot prefix")
	errInvalidResponse = errors.New("Discord returned invalid data")
	errBodyLimit       = errors.New("Discord response exceeded the size limit")
)

type Identity struct {
	ApplicationID string
	BotUserID     string
	Name          string
	Flags         *uint64 // Published application flags, when Discord includes them.
}

type api struct {
	client *http.Client
}

var discordAPI = api{client: newHTTPClient()}

func newHTTPClient() *http.Client {
	dialer := &net.Dialer{Timeout: 5 * time.Second}
	return &http.Client{
		Timeout:       10 * time.Second,
		CheckRedirect: func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse },
		Transport: &http.Transport{
			// Never use environment proxies for requests carrying bot credentials.
			DialContext:            dialer.DialContext,
			TLSClientConfig:        &tls.Config{MinVersion: tls.VersionTLS12},
			TLSHandshakeTimeout:    5 * time.Second,
			MaxResponseHeaderBytes: 64 << 10,
			DisableKeepAlives:      true,
			DisableCompression:     true,
		},
	}
}

// LookupIdentity uses the raw bot token to look up its application and bot user.
func LookupIdentity(ctx context.Context, token string) (Identity, error) {
	return discordAPI.lookupIdentity(ctx, token)
}

func (a api) lookupIdentity(ctx context.Context, token string) (Identity, error) {
	if !validToken(token) {
		return Identity{}, errInvalidToken
	}
	var application struct {
		ID       string  `json:"id"`
		Name     string  `json:"name"`
		Flags    *uint64 `json:"flags"`
		FlagsNew string  `json:"flags_new"`
		Bot      *struct {
			ID string `json:"id"`
		} `json:"bot"`
	}
	if err := a.get(ctx, token, "/applications/@me", &application); err != nil {
		return Identity{}, fmt.Errorf("look up Discord application: %w", err)
	}
	if _, ok := snowflake(application.ID); !ok {
		return Identity{}, errors.New("Discord did not return a valid application ID")
	}

	var user struct {
		ID       string `json:"id"`
		Username string `json:"username"`
		Bot      bool   `json:"bot"`
	}
	if err := a.get(ctx, token, "/users/@me", &user); err != nil {
		return Identity{}, fmt.Errorf("look up Discord bot user: %w", err)
	}
	if _, ok := snowflake(user.ID); !ok || !user.Bot {
		return Identity{}, errors.New("Discord did not return a valid bot user")
	}
	if application.Bot != nil && application.Bot.ID != user.ID {
		return Identity{}, errors.New("Discord returned different bot users for the same token")
	}

	name := safeName(user.Username, token)
	if name == "" {
		name = displayName(application.Name, user.ID, token)
	}
	flags := application.Flags
	if value, err := strconv.ParseUint(application.FlagsNew, 10, 64); err == nil {
		flags = &value
	}
	return Identity{ApplicationID: application.ID, BotUserID: user.ID, Name: name, Flags: flags}, nil
}

func (a api) get(ctx context.Context, token, endpoint string, out any) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, baseURL+endpoint, nil)
	if err != nil {
		return errors.New("could not prepare Discord request")
	}
	req.Header.Set("Authorization", "Bot "+token)
	req.Header.Set("User-Agent", "DiscordBot (https://github.com/thirdscam/chatanium, 1)")
	resp, err := a.client.Do(req)
	if err != nil {
		return requestError(ctx, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		switch resp.StatusCode {
		case http.StatusUnauthorized:
			return errors.New("Discord rejected the bot token (HTTP 401)")
		case http.StatusForbidden:
			return errors.New("the bot does not have access (HTTP 403)")
		case http.StatusTooManyRequests:
			return errors.New("Discord rate limited the request (HTTP 429); try again later")
		default:
			return fmt.Errorf("Discord returned HTTP %d", resp.StatusCode)
		}
	}
	if resp.ContentLength > maxBodyBytes {
		return errBodyLimit
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, maxBodyBytes+1))
	if err != nil {
		return requestError(ctx, err)
	}
	if len(body) > maxBodyBytes {
		return errBodyLimit
	}
	if err := json.Unmarshal(body, out); err != nil {
		return errInvalidResponse
	}
	return nil
}

func requestError(ctx context.Context, err error) error {
	if ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return errors.New("could not communicate with Discord")
}

func validToken(token string) bool {
	if token == "" || len(token) > 1024 {
		return false
	}
	for i := range len(token) {
		if token[i] < '!' || token[i] > '~' {
			return false
		}
	}
	return true
}

func snowflake(id string) (uint64, bool) {
	if len(id) == 0 || len(id) > 20 || id[0] < '1' || id[0] > '9' {
		return 0, false
	}
	n, err := strconv.ParseUint(id, 10, 64)
	return n, err == nil
}

func displayName(name, id, token string) string {
	if label := safeName(name, token); label != "" {
		return label
	}
	return id
}

func safeName(name, token string) string {
	if strings.Contains(name, token) {
		return ""
	}
	label := strings.TrimSpace(strings.Map(func(r rune) rune {
		if unicode.IsSpace(r) {
			return ' '
		}
		if !unicode.IsPrint(r) {
			return -1
		}
		return r
	}, name))
	if strings.Contains(label, token) {
		return ""
	}
	n := 0
	for i := range label {
		if n == maxNameRunes {
			return label[:i]
		}
		n++
	}
	return label
}
