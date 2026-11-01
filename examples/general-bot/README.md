# Ordinary Discord v2 module

`examples/general-bot` is the generic bot example (output `bin/test-module`). It uses the real `core-v2` bootstrap,
module-owned JSON storage, typed `discord-v2` events/helpers, and explicit upload
streams. It does not import the old broker, Discord v1, voice, native DAVE, or any
media provider. No internet grant, privileged Gateway intent, FFmpeg, yt-dlp,
Deno, host installation, or module-side bot token is needed for the basic command
path. Credentials stay on the host; interaction handles contain opaque refs.

From the repository root, build the ordinary runtime and module with `make build`, then
build its ordinary OCI image with `make image-module`. The host runtime launches
the pinned image through the authenticated sandbox broker; this executable is
not a host-side token/configuration loader. `manifest.json` is the **single
canonical protobuf-JSON manifest**, embedded by `main.go`; the image builder must
use these exact bytes for `org.chatanium.flexmodule.manifest.v2`.

## Operator configuration

The host supplies one strict JSON object through `Core.GetConfig`. Unknown fields,
non-object JSON, malformed IDs, duplicate configured IDs, cross-guild channel
reuse, and invalid finite limits fail INIT. Nothing is read from host environment
variables by the module. Generate the following configuration **on the operator
side**, with IDs explicitly approved for this installation:

```sh
jq -n \
  --arg application_id "$APPROVED_APPLICATION_ID" \
  --arg guild_id "$APPROVED_GUILD_ID" \
  --arg channel_id "$APPROVED_TEXT_CHANNEL_ID" '
  {
    application_id: $application_id,
    guilds: [{
      guild_id: $guild_id,
      text_channel_ids: [$channel_id],
      audit_channel_ids: [$channel_id],
      moderation: {
        enabled: false,
        approved_member_ids: [],
        approved_role_ids: [],
        approved_ban_user_ids: [],
        approved_timeout_user_ids: [],
        allowed_parent_ids: [],
        max_timeout_seconds: 60
      }
    }],
    allow_dm: false,
    enable_messages: false,
    enable_forms: true,
    enable_attachments: true,
    operation_timeout_seconds: 30
  }' > general-config.json
```

No destructive target is invented in that configuration. To enable moderation,
set the guild's `moderation.enabled` to true and explicitly populate the lists
for the actions you approve. Role changes use `approved_member_ids` **and**
`approved_role_ids`; bans/unbans and timeouts/clear-timeouts have separate approved
user lists. An empty list authorizes no targets. `allowed_parent_ids` allows only
explicit category IDs. Names for newly created/renamed channels must start with
`flex-test-` and fit 80 bytes; creation permits only text channels or categories.
All channel edits/deletions additionally require this module's durable record
that it created that exact channel in that exact guild.

The precise field types are `GeneralExampleConfig`, `GuildConfig`, and
`ModerationConfig` in `config.go`. Bounds:

- `application_id` and every supplied resource ID are nonzero decimal uint64 IDs.
- At most 32 guilds; each guild has 1–64 approved text channels, at most 64 audit
  channels, and at most 64 entries in each moderation/parent approval list.
- Audit channels must be in that guild's approved text-channel list.
- `operation_timeout_seconds` is mandatory and must be 1–120.
- Enabled moderation requires `max_timeout_seconds` between 1 and 2,419,200 (28 days).
- At least one guild or `allow_dm=true` is required. DM management is never
  redirected into a configured guild. `allow_dm=true` permits the bot-DM context;
  it does not grant user-install or arbitrary private-channel integration types.

## Grants and optional features

The manifest declares the resource-free `core.config.read` requirement and an
optional resource-free `core.upload` request. It requires Discord protocol major
2. Its Discord operation requests are optional `allResources` **ceilings**, not
actual grants. This lets the operator narrow approval to concrete installation
IDs without baking private deployment IDs into the image. INIT checks the actual
immutable grants, not the manifest, and fails if its configured basic path cannot
run. Do not approve `allResources` merely because the image requests a ceiling.

The basic path requires:

- `discord.rest.ApplicationCommandCreate` scoped to the application and configured
  guild (application scope for the DM/global registration).
- `discord.event.INTERACTION_CREATE`, `discord.rest.InteractionRespond`, and
  `discord.rest.WebhookMessageEdit` for every approved application/guild/source
  channel. These support typed command delivery, response, and explicit defer/edit.
- A nonzero persistent quota and a canonical absolute persistent directory supplied
  by the authenticated `InitContext`. The current host mounts it at
  `/var/lib/flexmodule/data`; the module does not hardcode that spelling.

Optional features are enabled only when configured and compatible actual grants
exist. Each management command is decided independently: missing ban, role, or
timeout grants never disable member lookup or owned-channel CRUD. Empty target
approval lists do not request those actions. Unavailable commands are omitted
from registration and listed individually in `GetStatus.detail`. A real
registration collision or storage error still fails initialization.

Interaction/event INIT checks compare known application/guild/channel IDs while
allowing additional authenticated-caller or interaction-ID constraints whose
values are not available yet. This is compatibility preflight, **not** operation
authorization. The host checks the full actual scope on every delivered event
and RPC. Known mutation targets always use complete local scope checks too.

| Feature | Additional capabilities and scope |
|---|---|
| Forms | `discord.routes.manage` at the configured application; the basic interaction grants still apply. |
| Message create/update/delete demo | `discord.event.MESSAGE_CREATE`, `.MESSAGE_UPDATE`, `.MESSAGE_DELETE` and `discord.rest.ChannelMessageSendComplex`, `.ChannelMessageEditComplex`, `.ChannelMessageDelete` for each approved text channel. |
| Attachments | `core.upload`; the three channel-message operations above at each configured channel; `discord.rest.WebhookThreadExecute`, `.WebhookMessageEdit`, `.WebhookMessageDelete` compatible with each configured application/guild/channel and future authenticated caller. No guild-wide webhook grant or message-event grant is required. |
| Member info | `discord.rest.GuildMember` at an entry in `approved_member_ids`. Role IDs come from that actual member; optional guild-wide `.GuildRoles` only enriches display names when separately granted. |
| Role add/remove | The corresponding `.GuildMemberRoleAdd` or `.GuildMemberRoleRemove` must separately cover an approved user leaf and an approved role leaf. Both local approval lists apply; a conjunction containing both IDs is not a substitute for the backend's separate resource checks. |
| Ban/unban and timeout | Only their corresponding operation and approved user leaf are checked. Empty ban/timeout lists leave only those commands unavailable, without requiring those capabilities. |
| Owned channel edit/delete | The corresponding `.ChannelEdit` or `.ChannelDelete` must cover the exact channel ID in this module's durable created-channel records. A grant without ownership or ownership without a grant is insufficient. Setting a parent additionally requires that operation's approved parent-channel scope. |
| Channel creation / audit | `.GuildChannelCreateComplex` requires genuine guild-root mutation authority; unfiltered `.GuildAuditLog` requires guild authority. Neither is channel-limited, and neither is a prerequisite for other management commands. Audit-message delivery separately checks the approved saved channel's `.ChannelMessageSendComplex` grant. |

DM message-channel IDs are not known at INIT. The ordinary-channel part of the
DM attachment/message demonstration still needs actual channel-operation scope;
the current example cannot preflight a new arbitrary DM channel from a fixed
allowlist. Otherwise that optional group is disabled. This is not a reason to
approve `allResources`: guild-only installations can keep every ordinary message
operation narrowly scoped. DM slash commands/forms use compatible application
and future authenticated-caller interaction grants; known guild absence is
checked, so a guild-only grant is not borrowed for a DM.

Newly created channel IDs do not exist at INIT. For narrow owned-resource grants,
use two explicit operator phases: create with approved guild-root creation
authority, record the returned ID, then stop/reload with exact edit/delete grants
for that ID. The same persistent mount preserves ownership. Do not pre-authorize
all channels merely to avoid this explicit approval boundary. With explicit
guild-wide channel-edit/delete authority those commands can be available before
creation, but the example still refuses to mutate a channel it did not create.

The ordinary basic path does not request member/presence events or voice. Message
content may be absent without privileged `MESSAGE_CONTENT`; such a guild event
is normal, not an excuse to widen intents. Operators wanting the `ping` text demo
must use a Discord context where its content is actually available (for example
a bot DM), plus the corresponding nonprivileged message intents. The host still
independently enforces all event intents, verified resource relationships,
instance admission, credential purpose/expiry, and Discord permissions.

## Behavior

- `/hello` returns a typed initial response with an embed, disabled mentions, and
  ephemeral flags. Basic commands preserve unset `DefaultMemberPermissions`.
  Registration uses `ApplicationCommandView`; a returned Discord null permission
  is preserved separately from absence and explicit zero. Callback authorization
  retains the configured permission requirement, not a response-derived fallback.
- `/permission-check` preserves explicit **zero** default member permissions and
  admits only a Discord administrator. `/settings` requires the combined
  `ManageGuild | ViewAuditLogs` mask. Other management commands carry their actual
  Discord permission bit. The callback checks caller permissions too; a runtime
  grant is never treated as an end-user permission grant.
- `/settings [channel]` reads/saves an approved audit response channel. Without
  `channel` it distinguishes absent settings from an explicitly saved value.
- `/member-info`, `/role-add`, `/role-remove`, `/channel-create`, `/channel-edit`,
  `/channel-delete`, `/ban`, `/unban`, `/timeout`, `/clear-timeout`, `/audit-log`
  invoke the corresponding typed helpers. Mutations carry an explicit audit
  reason and no automatic resend. Ban deletion history is zero days. Member info
  tolerates a partial member with no user; it does not fabricate one.
- Channel edit distinguishes omission, explicit slowmode zero, empty topic, null
  parent, and an explicit empty permission-overwrite list. Contradictory set/clear
  options fail before a remote mutation. Timeout clear uses the nullable timestamp
  null variant, not a missing timestamp.
- Audit replies display only permission/position/slowmode changes and their exact
  old/new JSON bytes, distinguishing absent from JSON null; no float re-decoding or
  raw audit/credential dump is used. An approved saved channel receives the reply.
- `/form [topic]` registers autocomplete and responds with a button and select.
  Either opens a typed feedback modal; submit reads exactly one actual child input.
  Component/modal/accessor selection happens **after** checking the interaction
  kind. The focused autocomplete option produces matching typed string choices.
- Exact route claims are `(application_id, MESSAGE_COMPONENT,
  flex.general.form.open)`, `(application_id, MESSAGE_COMPONENT,
  flex.general.form.topic)`, and `(application_id, MODAL_SUBMIT,
  flex.general.form.submit)`. The modal child `feedback` is not a route claim.
  The entire batch is claimed before any interactive payload is sent and released
  in DRAIN. No custom-ID prefix routing or bulk command deletion is implemented.
- With message examples enabled, a human `ping` creates an owned bot reply in the
  actual guild/DM source channel. A distinct content update edits that reply; a
  distinct delete deletes it. Nil authors, partial updates, and absent cached
  before snapshots are normal. At most 128 original/reply pairs are tracked in
  memory; reaching the bound gives an explicit capacity response. This state is
  not replayed after restart and never authorizes editing/deleting unrelated
  messages.
- `/attachment-demo` explicitly defers, streams a complete one-pixel PNG using
  `core.FileClient.Upload`, reuses its completed owner-bound ref across an edited
  original response, a follow-up, and an ordinary channel message, then deletes
  only its demonstration messages. Both response and ordinary message edits use
  a complete retained-ID/new-file-index-**0** attachment set and matching
  `attachment://filename` embeds.
  The initial original/ordinary uploads are not referenced by embeds: Discord
  returns only files **not referenced in embeds or components** in
  [`Message.attachments`](https://docs.discord.com/developers/resources/message#message-object-message-structure).
  This makes their actual returned attachment IDs available for retention;
  the following retain-and-add edits embed the newly added `second.png`.
  Embedded attachment IDs are never inferred from CDN URLs or fabricated.
  Empty content is demonstrated while a real embed/file remains; subsequent edits
  clear embeds/components/attachments with
  explicit empty lists while retaining nonempty text, because Discord rejects
  an entirely empty message. Follow-up edit/delete are separate real operations.
  The upload is deleted explicitly and again during cleanup, exercising finite
  owner tombstones. Errors in mutation, upload, or cleanup are propagated.

All helper calls are context-first. Finite management/file commands explicitly
choose defer before work and use response-edit afterward; helpers do not secretly
defer, upload, or retry. Expected command rejections receive a safe failure
response rather than a false success. Failed reporting preserves both causes;
unhandled internal/durability errors still fail the event. Diagnostics never dump
tokens, refs, original interaction payloads, or raw Discord errors.

## Storage and lifecycle

INIT validates config and actual scoped grants, opens settings, claims routes,
and registers commands by their actual returned IDs before publishing readiness.
START returns without waiting on RUNNING-only work. Each event has a finite
operation deadline and is tied to the instance lifetime. DRAIN rejects new work,
cancels admitted callbacks, waits for them, and releases only owned exact routes
within its caller deadline; STOP joins and closes storage. It does not bulk-delete
commands or delete persistent data.

`settings.json` under `InitContext.PersistentDirectory` is schema version **1** with `guilds` and
`created_channels` maps. The latter stores only channel-to-guild ownership records,
not credentials, events, upload refs, or host paths. Settings survive restart and
image change with the same module persistent mount.

The directory is consumed exactly as supplied after canonical absolute/non-root
validation, not compared against a legacy mount alias. All temporary writes,
rename, sync, reopen and cleanup are relative to its `os.Root`. The ordinary
module does not use `InitContext.ScratchDirectory`: its small fixed attachment
is streamed from memory and completed upload refs are deleted through the core
file helper, not converted to guest or host paths.

A missing first-install file
starts empty; corrupt/unsupported/unknown-field state fails initialization without
overwriting it. Symlinked settings files are rejected. Updates serialize through
a lock, write a random exclusive same-directory mode-0600 temporary file, fsync
and close it, rename atomically, and fsync the directory. A post-rename fsync error
poisons further writes instead of pretending durability or reverting to memory.
If a remote channel change succeeds but durable ownership recording fails, the
safe error identifies that exact changed channel and makes no rollback/retry claim.

The backend/storage owner enforces 256 KiB upload chunks, its separate 500 MiB
storage limit, 30-minute completed-ref TTL, active read leases, and instance-bound
ownership. This tiny example does not promise Discord accepts a 500 MiB payload,
retain refs across restarts, sleep until expiry, or relax endpoint size limits.

## Validation boundary

`settings_test.go`, `behavior_test.go`, and `management_test.go` contain
deterministic storage restart, corruption/symlink, cancellation, presence/zero/null,
identity/scope, duplicate modal input, and error-cause regressions. Management
regressions exercise INIT's actual preflight/planning functions, registration
visibility, and a stateful offline gRPC helper boundary: dev-user constraints are
preserved, unrelated ban/role/timeout grants are unnecessary, and owned-but-
ungranted or granted-but-unowned channels remain unchanged. These fixtures are
not a production fallback or proof of a full sandbox lifecycle. Parent integration
owns formatting, builds, tests, OCI image creation, actual sandbox checks, and
approved Discord smoke. No live Discord, container isolation, image-build, or
new test-execution success is claimed by these source changes.
