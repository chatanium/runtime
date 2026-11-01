package discordbackend

import (
	"fmt"
	"strings"
	"testing"

	"github.com/bwmarrin/discordgo"
	runtime "github.com/thirdscam/chatanium/internal/runtime"
	corewire "github.com/thirdscam/chatanium/proto/core-v2"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
)

func TestInteractionEventScopePreservesInvokerInsteadOfMessageAuthor(t *testing.T) {
	b := &Backend{session: &discordgo.Session{}}
	for _, actor := range []struct {
		name  string
		field string
		guild string
	}{
		{"guild", `"member":{"user":{"id":"40"}},"guild_id":"10",`, "10"},
		{"dm", `"user":{"id":"40"},`, ""},
	} {
		for _, interaction := range []struct {
			name string
			data string
		}{
			{"component", `"type":3,"data":{"custom_id":"flex.general.form.open","component_type":2}`},
			{"modal", `"type":5,"data":{"custom_id":"flex.general.form.submit","components":[]}`},
		} {
			t.Run(actor.name+"/"+interaction.name, func(t *testing.T) {
				raw := fmt.Sprintf(`{"id":"50","application_id":"20","channel_id":"30",%s%s,"message":{"id":"70","channel_id":"30","application_id":"20","author":{"id":"90","bot":true}}}`, actor.field, interaction.data)
				ids := map[string]string{"application_id": "20", "channel_id": "30", "user_id": "40"}
				if actor.guild != "" {
					ids["guild_id"] = actor.guild
				}
				grant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(ids)}}
				check := func(raw string) error {
					t.Helper()
					target, err := b.eventScope("INTERACTION_CREATE", []byte(raw))
					if err != nil {
						t.Fatal(err)
					}
					return eventResourceGraph("INTERACTION_CREATE", []byte(raw), target, grant)
				}
				if err := check(raw); err != nil {
					t.Fatalf("bot-authored originating message replaced invoking user: %v", err)
				}
				target, err := b.eventScope("INTERACTION_CREATE", []byte(raw))
				if err != nil {
					t.Fatal(err)
				}
				if target.GetSelector().ResourceIds["user_id"] != "40" {
					t.Fatal("event scope lost top-level invoking user")
				}
				if err := resourceGraph([]byte(raw), "", target.GetSelector().ResourceIds, grant, 0); status.Code(err) != codes.PermissionDenied {
					t.Fatal("fixture no longer exercises author/invoker distinction")
				}
				for _, denied := range []struct {
					name string
					from string
					to   string
				}{
					{"invoker", `"id":"40"`, `"id":"41"`},
					{"application", `"application_id":"20"`, `"application_id":"21"`},
					{"channel", `"channel_id":"30"`, `"channel_id":"31"`},
					{"message-application", `"message":{"id":"70","channel_id":"30","application_id":"20"`, `"message":{"id":"70","channel_id":"30","application_id":"21"`},
					{"message-channel", `"message":{"id":"70","channel_id":"30"`, `"message":{"id":"70","channel_id":"31"`},
					{"related-user", `"author":`, `"user":{"id":"41"},"author":`},
					{"author-relationship", `"bot":true`, `"bot":true,"channel_id":"31"`},
				} {
					t.Run(denied.name, func(t *testing.T) {
						if err := check(strings.Replace(raw, denied.from, denied.to, 1)); status.Code(err) != codes.PermissionDenied {
							t.Fatalf("out-of-scope relationship was not denied: %v", err)
						}
					})
				}
				if actor.guild != "" {
					for _, denied := range []string{
						strings.Replace(raw, `"guild_id":"10"`, `"guild_id":"11"`, 1),
						strings.Replace(raw, `"message":{`, `"message":{"guild_id":"11",`, 1),
					} {
						if err := check(denied); status.Code(err) != codes.PermissionDenied {
							t.Fatalf("out-of-scope guild was not denied: %v", err)
						}
					}
				}
				if err := check(strings.Replace(raw, `"id":"90"`, `"id":"invalid"`, 1)); err == nil {
					t.Fatal("informational author bypassed ID validation")
				}
				if target.GetSelector().ResourceIds["user_id"] != "40" || ids["user_id"] != "40" {
					t.Fatal("event authorization mutated invocation scope or grant")
				}
			})
		}
	}
}

func TestNonInteractionEventScopeStillChecksMessageAuthorAndTarget(t *testing.T) {
	b := &Backend{}
	raw := []byte(`{"id":"70","guild_id":"10","channel_id":"30","author":{"id":"90","bot":true}}`)
	target, err := b.eventScope("MESSAGE_CREATE", raw)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name    string
		user    string
		message string
		allowed bool
	}{
		{"author", "90", "70", true},
		{"other-user", "40", "70", false},
		{"other-message", "90", "71", false},
	} {
		t.Run(test.name, func(t *testing.T) {
			grant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{scope(map[string]string{"guild_id": "10", "channel_id": "30", "message_id": test.message, "user_id": test.user})}}
			// Even inherited user context must not make a noninteraction's
			// author informational. The other-user case passes the root check.
			parent := scope(map[string]string{"guild_id": "10", "channel_id": "30", "message_id": "70", "user_id": test.user})
			if target.GetSelector().ResourceIds["message_id"] != "70" {
				t.Fatal("message event scope lost target identity")
			}
			err := eventResourceGraph("MESSAGE_CREATE", raw, parent, grant)
			if test.allowed && err != nil {
				t.Fatalf("allowed message author was denied: %v", err)
			}
			if !test.allowed && status.Code(err) != codes.PermissionDenied {
				t.Fatalf("message author or target scope was bypassed: %v", err)
			}
		})
	}
}

func TestMessageEventScopeUsesPresentRootAuthorBeforeRuntimeAdmission(t *testing.T) {
	b := &Backend{}
	grant := &corewire.CapabilityGrant{ResourceScopes: []*corewire.ResourceScope{
		scope(map[string]string{"guild_id": "10", "channel_id": "30", "user_id": "40"}),
	}}
	for _, name := range []string{"MESSAGE_CREATE", "MESSAGE_UPDATE"} {
		t.Run(name, func(t *testing.T) {
			raw := []byte(`{"id":"70","guild_id":"10","channel_id":"30","author":{"id":"40","bot":false},"attachments":[{"id":"80","filename":"tone.wav","size":576044}]}`)
			target, err := b.eventScope(name, raw)
			if err != nil {
				t.Fatal(err)
			}
			if target.GetSelector().ResourceIds["user_id"] != "40" {
				t.Fatal("root message author was absent from the admission selector")
			}
			// Dispatcher checks the selector before invoking Recipient or Project.
			// A later recursive author check cannot repair this earlier omission.
			if !runtime.ResourceScopesSubset([]*corewire.ResourceScope{target}, grant.ResourceScopes) {
				t.Fatal("runtime admission silently excludes the approved message author")
			}
			if err = eventResourceGraph(name, raw, target, grant); err != nil {
				t.Fatal("approved message author failed recursive authorization")
			}
			for _, denied := range []struct{ from, to string }{
				{`"guild_id":"10"`, `"guild_id":"11"`},
				{`"channel_id":"30"`, `"channel_id":"31"`},
				{`"id":"40"`, `"id":"41"`},
			} {
				changed := []byte(strings.Replace(string(raw), denied.from, denied.to, 1))
				outside, err := b.eventScope(name, changed)
				if err != nil {
					t.Fatal(err)
				}
				if runtime.ResourceScopesSubset([]*corewire.ResourceScope{outside}, grant.ResourceScopes) {
					t.Fatal("an out-of-scope message passed the runtime selector gate")
				}
			}
			if _, err = b.eventScope(name, []byte(`{"id":"70","guild_id":"10","channel_id":"30","author":{"id":"invalid"}}`)); err == nil {
				t.Fatal("invalid root author ID became admission authority")
			}
		})
	}
	for _, tc := range []struct{ name, raw string }{
		{"MESSAGE_CREATE", `{"id":"70","guild_id":"10","channel_id":"30","author":null}`},
		{"MESSAGE_UPDATE", `{"id":"70","guild_id":"10","channel_id":"30","member":{"user":{"id":"40"}},"referenced_message":{"author":{"id":"40"}}}`},
		{"MESSAGE_DELETE", `{"id":"70","guild_id":"10","channel_id":"30","author":{"id":"40"}}`},
	} {
		t.Run(tc.name+"/missing-authority", func(t *testing.T) {
			target, err := b.eventScope(tc.name, []byte(tc.raw))
			if err != nil {
				t.Fatal(err)
			}
			if target.GetSelector().ResourceIds["user_id"] != "" || runtime.ResourceScopesSubset([]*corewire.ResourceScope{target}, grant.ResourceScopes) {
				t.Fatal("partial or delete payload invented root-author authority")
			}
		})
	}
}
