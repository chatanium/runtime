package discordbackend

import corewire "github.com/thirdscam/chatanium/proto/core-v2"

func apiFixturePointer[T any](value T) *T { return &value }

func apiFixtureCredential(purpose string) *corewire.CredentialRef {
	return &corewire.CredentialRef{OpaqueId: "fixture", BackendId: "discord", Purpose: purpose, ResourceScope: &corewire.ResourceSelector{ResourceIds: map[string]string{"application_id": "123", "guild_id": "123", "channel_id": "123"}}}
}
