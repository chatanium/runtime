# Voice Player Module (protocol v2)

This optional media module accepts audio attachments only from explicitly configured guild/text-channel pairs and plays them in that pair's configured voice channel. DMs and unrelated guilds/channels are ignored; there is no default guild or channel. Attachment extensions are candidate filters, not proof of valid audio.

## Artifacts and trust boundaries

Source is in `modules/audio-player`, an independent Go module that requires
`github.com/bwmarrin/discordgo v0.29.1-0.20260214123928-f43dd94faaac`, matching the
root `go.mod` version authority. Its DiscordGo replacement is
`../../.tools/deps/discordgo`; the Chatanium SDK root replacement remains `../..`.
Run `make prepare-sdk` from the repository root before direct Go commands here,
and follow the root [shared-lease and revalidation instructions](../../README.md#pinned-builds-and-independent-artifacts).
The prepared source comes from the maintained upstream patch stack, not a
published fork dependency. Original upstream checksums belong to
`third_party/discordgo/upstream.sum`, not this module's `go.sum`.
The preserved executable name is `bin/voice-player-module`; the source move does
not change the manifest, ModuleID or image/grant contract.

From the repository root, `make build-media` builds the nested media modules; `make image-media` packages the pinned tools. Use the image through the v2 runtime's operator configuration and approved immutable image digest, not a host subprocess or a token-bearing module environment. Host Discord credentials remain exclusively in the host backend. Native DAVE is a dependency of the separately built voice-enabled host, never of this module.

`manifest.json` is the sole canonical embedded protobuf-JSON manifest. Image tooling copies its exact bytes into `org.chatanium.flexmodule.manifest.v2`; the manifest is an untrusted request, never an approval. Strict parsing rejects unknown manifest fields. The descriptive executable name does not authenticate a ModuleID.

Only the media image contains the pinned FFmpeg 9.0.2 tools, at `/opt/flexmodule/bin/ffmpeg` and `/opt/flexmodule/bin/ffprobe`. Artifact provenance and image inputs are in `tools/media/tool-lock.json`. The player does not search the host PATH, install tools, update tools, fetch components, or use yt-dlp. Ordinary module images do not require media tools.

INIT validates the complete FFmpeg version token: the pinned upstream git-tag build reports `n9.0.2`, while a release-archive build reports `9.0.2`. Both identify the required release; other versions, development revisions and `-dirty` suffixes are rejected. Image provenance and the immutable image approval remain the authority for the exact tool bytes.

## Configuration and approvals

Core.GetConfig supplies the following structure. Replace every bracketed ID with an operator-approved Discord snowflake; these are not runnable personal IDs. Every numeric bound and duration is mandatory. `priority` and `max_redirects` must be present even when explicitly zero. Durations use Go duration syntax.

```json
{
  "targets": [{
    "guild_id": "<approved-guild>",
    "text_channel_ids": ["<approved-text-channel>"],
    "voice_channel_id": "<approved-voice-channel>"
  }],
  "priority": 0,
  "limits": {
    "max_download_bytes": 16777216,
    "max_artifact_bytes": 33554432,
    "max_frames": 30000,
    "max_packet_bytes": 1275,
    "max_process_output_bytes": 16384,
    "bitrate_kbps": 128,
    "workers": 1,
    "queue_entries": 4,
    "max_redirects": 3,
    "http_timeout": "30s",
    "encode_timeout": "60s",
    "job_lifetime": "15m",
    "operation_timeout": "10s",
    "cleanup_timeout": "5s"
  }
}
```

The numbers above illustrate explicit operator policy, not hidden defaults or a claim that the host permits these limits. Host voice-service limits must independently allow the chosen packet bound, priority, and job lifetime. Worker scratch reservation covers each worker's maximum download plus complete encoded artifact. Queue accounting includes waiting and active entries. Process, scratch and queue-memory bounds must fit the actual granted resource limits. Configuration has no host filesystem paths, binary paths, credentials, module identity, arbitrary headers or alternative helper endpoints.

Required core grants use the resource-free empty selector for this authenticated instance:

- `core.config.read`
- `core.network.public_egress`, together with actual `PUBLIC_INTERNET` egress policy

The Discord backend must be available at major 2. The canonical manifest declares the following scoped capabilities as optional because their exact resource IDs are installation-specific. INIT nevertheless requires **every capability and every configured scope** below; a partial approval cannot silently enable a subset of the player's configuration:

| Capability | Required actual resource scope |
| --- | --- |
| `discord.event.MESSAGE_CREATE` | A scope compatible with each approved text channel and its `guild_id`; additional event identity constraints remain required at dispatch |
| `discord.rest.ChannelMessageSendComplex` | Each approved text channel and its `guild_id` |
| `discord.rest.Channel` | Each approved text/voice channel and its `guild_id` |
| `discord.voice.play` | Each configured voice channel and its `guild_id` |

Selector entries are conjunctions; the scope list is a disjunction. During INIT, the MESSAGE_CREATE preflight checks that grant constraints on known configured `guild_id`/`channel_id` do not conflict. Additional constraints such as `user_id` describe future authenticated events and are preserved, not treated as missing startup authority. The runtime must still match **every** selector entry before delivering each event; this compatibility check is not authorization. Channel helpers and voice operations still require complete target scope checks: an extra user/message restriction that their request cannot satisfy is not accepted. `discord.voice.play` also needs the actual typed `VoicePlaybackConstraints` with `max_priority` at least the configured priority. An operator-wide `all_resources` approval is not required or inferred from the manifest.

Gateway intents and Discord permissions are separate host-side prerequisites: the backend must have the needed guild-message/message-content delivery and voice-state intents, and the bot must actually be allowed to view/reply/connect/speak. Media CPU/memory policy grants neither internet nor voice. Public-egress approval still forbids host/private/link-local/metadata/internal destinations under the sandbox's real IPv4/IPv6 firewall.

## Lifecycle and playback

INIT reads configuration and actual grants, validates finite limits, opens the authenticated `InitContext.scratch_directory`, creates a private generated instance subtree there, and validates the pinned encoder with its working directory, HOME and TMPDIR inside that owned subtree. There is no `/scratch` or `/persistent` convention or fallback. It reports ready only after those steps succeed; failed encoder validation removes only the newly owned subtree. START launches instance-owned workers and returns without waiting for RUNNING-only helpers. A bounded background validation step resolves every configured channel through the typed Channel helper and verifies its actual guild and text/voice type. Until that completes, incoming attachment batches are explicitly rejected rather than played. Validation failure is exposed as failed status and a hook error on subsequent delivery. This player does not use or modify persistent settings.

OnEvent decodes only the declared typed MESSAGE_CREATE payload, tolerates absent author/partial fields, ignores bots, and admits a bounded batch without retaining its callback context or work reference. The immediate reply means only “accepted”; it never means playback succeeded. Long preparation/playback runs under the instance lifetime and the configured finite HTTP, encoding and job deadlines.

Downloads use context-bound HTTP requests, a finite redirect count/deadline/concurrency, successful status checks, early Content-Length rejection, and actual-byte enforcement through limit+1 reading. URL credentials/fragments are rejected. URLs are not logged. URL syntax checks are not an SSRF isolation claim: real destination enforcement belongs to the sandbox, including redirects, DNS changes and subprocesses.

Attachment filenames are display/candidate metadata only. Random exclusive-created file names in private `os.Root`-confined scratch directories prevent filename traversal, absolute-path, duplicate-name and symlink escape. Encoding publishes only a complete bounded Opus artifact after encoder exit, close and frame validation; one valid 20ms frame is sufficient, while empty/truncated/invalid input is a failure.

Playback uses only the P5 owned-job API and `ProducePlayback`: both frame and maximum-packet byte credits are obtained before every decoder read, EOF sends EndInput and half-closes, and the receiver remains alive until the actual terminal snapshot. There is no pacing sleep, raw OpusSend channel, Join/Leave, speaking control, fake frame, fallback stream, replay or automatic retry. Only terminal COMPLETED produces a completion reply. UDP-written counters do not prove audible delivery.

DRAIN stops admission, cancels instance work and owned jobs, waits for workers within the supplied deadline, and releases only this instance's processes, streams, files and scratch subtree. It never disconnects another owner's voice connection or removes persistent data. STOP repeats owned cleanup safely. Preparation/playback errors are reported as failures; a failed error-reporting helper also marks the module failed rather than recording success.

## Validation status

The source is an implementation, not evidence of a successful live deployment. Parent integration runs offline tests and media builds separately from real sandbox and approved-channel voice smoke. Actual DAVE/AEAD negotiation, another participant's receive stream, and audible playback require the separately approved live voice setup; missing prerequisites must be reported as NOT_RUN, never PASS.
