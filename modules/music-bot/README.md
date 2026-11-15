# Chatanium MusicBot (FlexModule v2)

This optional media module resolves YouTube queries, prepares complete module-owned Opus artifacts, and streams them to the host's authenticated playback-job service. It does not join a Discord connection, hold voice credentials, pace packets, install software, or own the runtime scheduler. The ordinary bot is a separate example.

## Build and installation

Source is in `modules/music-bot`, an independent Go module that requires
`github.com/bwmarrin/discordgo v0.29.1-0.20260214123928-f43dd94faaac`, matching the
root `go.mod` version authority. Its DiscordGo replacement is
`../../.tools/deps/discordgo`; the Chatanium SDK root replacement remains `../..`.
Run `make prepare-sdk` from the repository root before direct Go commands here,
and follow the root [shared-lease and revalidation instructions](../../README.md#pinned-builds-and-independent-artifacts).
The prepared source comes from the maintained upstream patch stack, not a
published fork dependency. Original upstream checksums belong to
`third_party/discordgo/upstream.sum`, not this module's `go.sum`.
`make build-module music-bot` builds `bin/modules/music-bot/module`. Plain
`make build` includes this module automatically; its directory does not change
the manifest, ModuleID or image/grant contract.

Use `make image-media` to package the media modules and pinned tools. Run the music OCI image through the v2 runtime with its media resource profile, approved public Internet egress, and an actual voice-enabled Discord backend. `manifest.json` is the **only** manifest source: the executable embeds those bytes and the image builder uses the same file for `org.chatanium.flexmodule.manifest.v2`. The image label requests capabilities; it does not grant them.

The backend is required. Discord operations are optional manifest requests so installation can narrow their all-resource requests to the operator's exact scopes. INIT then requires every configured operation, scope, and voice priority constraint; missing grants fail readiness rather than silently disabling music. Required core capabilities are `core.config.read` and `core.network.public_egress`, with actual `PUBLIC_INTERNET` policy. Required configured Discord capabilities are:

- `discord.event.INTERACTION_CREATE`
- `discord.rest.ApplicationCommandCreate`
- `discord.rest.UserVoiceState`
- `discord.rest.InteractionRespond`
- `discord.rest.WebhookMessageEdit` (the canonical interaction response-edit helper)
- `discord.rest.ChannelMessageSendComplex`
- `discord.voice.play`, including a typed `VoicePlaybackConstraints.max_priority`

Approve the configured application, guild, text-channel, and voice-channel scopes. Discord's own bot and command-user permissions remain separate checks. Commands register individually under backend ownership; the module never bulk-deletes unrelated commands. Command IDs, not names alone, select callbacks. Guild-only contexts, guild-install integration type, and `UseApplicationCommands` default member permission are passed unchanged.

For `discord.event.INTERACTION_CREATE` only, INIT checks compatibility with configured application/guild/text-channel constraints while permitting additional future authenticated identity constraints such as an operator-approved `user_id`. It neither drops those constraints nor treats compatibility as permission to deliver an event: the host checks the complete actual event scope, including its authenticated user. A different configured application/guild/channel is still rejected. Helper and mutation grants retain strict complete-scope matching. `UserVoiceState` uses separate verified user and channel leaves; an approval can restrict the user leaf to the approved participant and the channel leaf to the dedicated voice channel without granting guild-wide user observation.

No host token, webhook secret, interaction token, Docker socket, host media tool, or host environment is needed or accepted by the module. Only the host reads its bot credential. The module receives owner-bound interaction credential references through typed events.

## Mandatory module configuration

Provide this object through core-v2 `GetConfig`, not environment variables. All fields in `limits` are required positive finite integers, including the redirect allowance; omitted/zero values are errors. `priority` is an explicit signed integer, checked against the actual voice grant. `guilds` must contain unique nonempty guild IDs and disjoint, nonempty text/voice channel lists. Use actual approved Discord IDs; none are compiled in.

| Field | Meaning |
| --- | --- |
| `application_id` | Application whose commands this module registers |
| `guilds[].guild_id` | Approved guild |
| `guilds[].text_channel_ids` | Channels accepting commands and task failure notices |
| `guilds[].voice_channel_ids` | Channels in which the invoking member may request playback |
| `priority` | P5 playback priority, no greater than the grant's maximum |
| `limits.max_input_bytes` | Actual downloaded source-file ceiling, independent of Content-Length |
| `limits.max_artifact_bytes` | Complete framed Opus artifact ceiling; also bounds encoder Ogg output |
| `limits.max_frames` | Maximum number of complete 20ms Opus frames; at most signed int64 |
| `limits.max_packet_bytes` | Individual Opus packet ceiling, at most 32767 and within host credit policy |
| `limits.max_process_output_bytes` | Each provider stdout/stderr ceiling and encoder diagnostic ceiling |
| `limits.max_results` | Ordered tracks returned by one resolve; at most queue capacity |
| `limits.workers` | Fixed instance-wide pool shared by resolve/download/encode work |
| `limits.queue_entries` | Per-guild current plus waiting reservation capacity |
| `limits.mailbox_entries` | Per-guild bounded command mailbox capacity |
| `limits.max_query_bytes` | Query input byte ceiling |
| `limits.resolve_timeout_ms` | One provider resolve deadline |
| `limits.prepare_timeout_ms` | One download-plus-encode preparation deadline |
| `limits.queue_timeout_ms` | Reservation/prepared-entry wait deadline, independent of callback lifetime |
| `limits.playback_timeout_ms` | Absolute P5 job and producer-stream lifetime, including preemption/pause |
| `limits.command_timeout_ms` | Finite command/control/reporting and owned-job cleanup allowance |
| `limits.tool_timeout_ms` | Deadline for each image tool version probe during INIT |
| `limits.http_timeout_ms` | HTTP request/body deadline, also bounded by preparation context |
| `limits.max_redirects` | Maximum HTTPS redirects for a source fetch |
| `limits.bitrate_kbps` | Encoder bitrate, 8–128 kb/s |

INIT requires the authenticated `InitContext.ScratchDirectory`, a clean absolute non-root directory, rather than a compiled-in guest mount name. It checks the scratch grant against conservative reservations: `guild_count * queue_entries * max_artifact_bytes`, plus `workers * (guild_count + 1) * max_artifact_bytes` for in-flight/cancelled results, plus `workers * max_input_bytes` for source files. The runtime's project quota also covers scratch caches and metadata; an exhausted quota is an error, not a fallback. Persistent playlists, playback cursors, and refs are intentionally not saved across instances.

The module creates one private generated scratch directory per instance. Neither track IDs, titles, URLs, nor user filenames determine a scratch filename. Source downloads check HTTPS, response status, Content-Length, actual bytes, redirects, cancellation, and deadlines. Host-side destination/network isolation remains necessary: URL validation is not an SSRF sandbox.

The instance child directory is created beneath that authenticated scratch mount. Provider HOME, TMPDIR, DENO_DIR, and subprocess working directory use a generated cache child; downloaded inputs, partial and completed artifacts use the instance child. The shared encoder derives HOME/TMPDIR/working directory from its generated input's owned parent. Cleanup removes only the generated instance child after work joins, never the authenticated mount or `InitContext.PersistentDirectory`. Music does not otherwise read or write persistent storage.

## Pinned media image

`tools/media/tool-lock.json` owns artifact provenance and checksums. INIT verifies executable identity and exact release versions at these fixed image paths:

| Tool | Version | Path |
| --- | --- | --- |
| FFmpeg | 9.0.2 | `/opt/flexmodule/bin/ffmpeg` |
| FFprobe | 9.0.2 | `/opt/flexmodule/bin/ffprobe` |
| yt-dlp | 2026.10.26 | `/opt/flexmodule/yt-dlp/yt-dlp` |
| Deno | 2.9.8 | `/opt/flexmodule/bin/deno` |

FFmpeg and FFprobe's pinned upstream git-tag build reports the exact version token `n9.0.2`; release-archive builds report `9.0.2`. INIT accepts those two release identities, while rejecting other versions and development/`-dirty` suffixes. yt-dlp and Deno retain their separate exact pinned-version checks. Image provenance and immutable image approval remain authoritative for the exact tool bytes.

The complete official yt-dlp onedir tree includes pinned EJS 0.8.0. The image, not a startup installer, supplies its interpreter/library/loader closure. The Go command builder remains pinned to `go-ytdlp v1.5.6`; only its explicit-executable command builder is used, never install/update/resolver APIs. Extraction disables config discovery, updates, remote components, cache discovery, and extractor/download retries, and explicitly selects the pinned Deno executable. Deno's writable cache is under owned scratch. Media subprocesses receive the fixed `LD_LIBRARY_PATH=/opt/flexmodule/lib`, not an inherited host search path. The shared encoder uses only local files and the approved executable, terminates/reaps its process group on cancellation, and bounds input, output, frames, packets, diagnostics, and lifetime. There is no DCA library, direct OpusSend channel, PATH lookup, `Join`, `Leave`, `Speaking`, fixed pacing sleep, update goroutine, or fake voice fallback.

## Commands and playlist semantics

- `/play provider:youtube query:...` explicitly defers, validates the member's actual approved voice channel, and accepts an ordered request ticket. It does not retain the callback or its delivery reference. Provider and preparation work use instance contexts and configured deadlines. Each unresolved request reserves `max_results` positions until resolution, so queue rejection can happen before the final result count is known.
- `/list` returns separate current and waiting entries, entry IDs, readiness/job state, loop mode, and the last task/reporting error. Large responses are bounded and explicitly marked when entries are omitted.
- `/remove entry:<ID>` removes only that waiting entry. Current removal is rejected; it cannot accidentally remove queue index zero. Pending preparation is cancelled and any eventual artifact is released.
- `/pause` and `/resume` control the current owned P5 job and report its returned state. Pause is no longer an ambiguous toggle.
- `/skip` cancels the current owned job and waits for its actual terminal stream boundary and reader/artifact release before reporting success or starting the next entry. A job still being created is explicitly not yet controllable. Unknown terminal outcomes stop further admission/advancement rather than replaying or guessing completion.
- `/loop enabled:<boolean>` changes actor-owned loop state. Only successful `COMPLETED` playback requeues the same entry at the tail; failed, skipped, and cancelled entries never loop. Priority preemption stays inside the same P5 job and never removes/recreates the current track.

One actor per configured guild exclusively owns its current item, waiting list, reservations, loop state, and command results. Resolve and preparation completion cannot reorder accepted requests or provider track order. Snapshot values are detached. A first prepared track can play before the remaining tracks finish downloading, but no partially written file is ever published READY. Successful preparation requires encoder success, flush, Sync/Close, complete bounded frame validation, and atomic publication. One-frame audio succeeds; frame-free audio is `EMPTY_AUDIO`. Partial reads, process failures, and partial JSON are failures, not empty successes.

Artifact queue owners and reader leases are independent; final-owner release removes the file, and repeated release by the same owner is harmless. Playback uses `ProducePlayback`, which waits for both frame and maximum-packet byte credit before every decoder read, sends explicit EndInput and half-close, and waits for a terminal snapshot. Decoder EOF is not playback completion. No automatic retry, reconnect, stream rebinding, media replay, or ten-second rate-limit sleep is performed.

DRAIN rejects new work, passes its remaining deadline into cleanup, cancels providers/preparation/streams, consumes outstanding worker results, joins the bounded worker and playback owners, and releases scratch only afterward. STOP is idempotent cleanup. A timeout is reported and the host retains responsibility for bounded forced instance termination.

## Source regressions and validation status

`state_test.go` covers reversed resolve/preparation completion, immutable current/waiting snapshots, waiting-only removal, failed reservation unblocking, successful-only loop, and skip waiting beyond decoder EOF and terminal RPC until the stream's artifact lease closes. `drain_test.go` checks cancellation consuming a late worker artifact and cleanup failure preventing false skip success or new reservations. `audio_test.go` covers one-frame/empty/truncated artifacts, byte/packet bounds, per-owner repeated release, and final-reader deletion. Provider tests reject partial/empty/oversized metadata and verify process-output overflow cancels instead of silently discarding bytes.

`producer_cleanup_test.go` ensures failure before the first producer snapshot still cancels the already-created job, releases its artifact, preserves the original error, and does not loop the cleanup cancellation.

Initial command callbacks retain the delivered typed application-command identity alongside the unchanged owner credential before either a defer or an early rejection response. Missing command data is rejected rather than filled with invented data. `interaction_response_test.go` exercises the actual SDK conversion boundary for defer-before-voice ordering, reporting a command-operation failure through the original response, and the draining rejection path.

`config_test.go` checks that INIT accepts a development-user-constrained interaction event grant unchanged, rejects mismatched application/guild/channel destinations, and does not apply partial event matching to helper mutations.

`scratch_test.go` checks nonliteral authenticated mounts, generated-file placement, sibling/persistent preservation during cleanup, and rejection of relative/aliased/symlink mount paths. `provider/scratch_test.go` uses an explicit child process that creates and closes real temporary, HOME, cache, and relative-output files; the parent verifies their bytes, containment in the nonstandard owned subtree, complete cleanup, and preservation of sibling storage. It does not assert environment/argument forwarding or require media tools.

These are source-level regression cases. Their presence is not evidence that tests, the OCI image, YouTube extraction, real Discord playback, DAVE transport, audible delivery, or sandbox isolation have been exercised. The integration owner runs formatting/build/offline suites and separately records actual approved-channel voice and sandbox evidence.
