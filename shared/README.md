# Protocol wrappers

This directory contains the Go module/runtime SDK for FlexModule v2. Generated
wire messages live in [`../proto`](../proto/README.md); host authorization and
execution live in `../internal/runtime` and `../internal/backend`, not in a module-side SDK.

## Packages

| Package | Responsibility |
|---|---|
| `core-v2` | Application protocol 2 bootstrap, Hook lifecycle/event dispatch, exact JSON config, FileTransfer client, common errors and work references |
| `discord-v2` | Typed Discord clients, event/domain conversion, presence-aware views, credential handles, interaction routes and optional voice-job client |
| `media/opus` | Optional module-side bounded FFmpeg/Opus processing; not a runtime backend or ordinary bot prerequisite |

The removed `core-v1`/`discord-v1`, old conversion utilities and helper-service
experiment are not compatibility paths. Rebuild runtime and modules together;
there is no mixed-version fallback.

The public Go module is `github.com/thirdscam/chatanium`; module authors import
its `shared/` SDK and `proto/` bindings. Host-only packages under
`internal/` are not module-author APIs. Discord types use the
`github.com/bwmarrin/discordgo` import path. The root `go.mod` pins upstream
`v0.29.1-0.20260214123928-f43dd94faaac` and replaces it with
`./.tools/deps/discordgo`; the nested media modules use the same requirement and
`../../.tools/deps/discordgo` replacement. This is the
[maintained upstream-plus-patches workflow](../third_party/discordgo/README.md),
not a dependency on a published fork or an unpatched-upstream fallback.

For host/runtime builds and the in-repository modules, run `make prepare-sdk`
from the repository root before direct Go commands. Repository build entry
points hold a shared SDK lease across compiler consumption. For raw Go commands,
prepare first and avoid concurrent dependency preparation; see the
[root build instructions](../README.md#pinned-builds-and-independent-artifacts).
`third_party/discordgo/upstream.sum`, not consumer `go.sum`, is the preparation
checksum authority.

Go replacements do not propagate to downstream consumers. Public `shared/`
users can consume the pinned upstream `github.com/bwmarrin/discordgo` DTO module
normally, without an SDK replacement; the host runtime needs the maintained
patches. Downstream modules must retain the pinned upstream DiscordGo version
or explicitly prepare the maintained patches for host use. No dependency on a
sibling FlexModule checkout is required. Host and live Discord behavior must be
validated separately from public SDK consumption.
These source boundaries do not change OCI manifests, ModuleIDs or grant checks.

## Transport and lifecycle

The privileged supervisor launches immutable module images through Docker/runsc.
The unprivileged runtime's manager uses the authenticated go-plugin
AutoMTLS/multiplex transport; modules are not launched directly as host
subprocesses. Each instance has a primary Hook connection and **one fixed reverse
helper connection**, broker ID 1, shared by core/file and registered backends.
The reverse-helper allowance is lifetime-scoped, not reset for each operation,
service or reconnect. Losing that transport fails the instance. An SDK helper
does not establish a new connection or invent authorization.

Modules implement `GetManifest`, `GetStatus`, `OnStage` and `OnEvent` using the
context-aware `core-v2` contract. The canonical embedded manifest must equal the
image label declaration after authenticated bootstrap. INIT validates module
configuration and **actual grants**, opens owned resources and publishes
readiness. START returns without blocking on RUNNING-only work. The runtime
commits RUNNING after START; its bounded activation gate handles eligible
early helper calls. Events are finite, ordered deliveries. DRAIN/STOP cancel,
join and release owned work within their deadlines.

Open module storage using the authenticated INIT values
`InitContext.persistent_directory` and `InitContext.scratch_directory`.
Do not hardcode directory names, including the current host implementation's
`/var/lib/flexmodule/data` and `/var/lib/flexmodule/scratch` paths.

ModuleID is an operator-assigned stable installation identity; InstanceID is
fresh per execution. Neither caller metadata nor `flexmodule-work-ref` creates
identity or grants. During drain, canonical finite Discord REST follow-ups and
finite voice controls/queries require the same authenticated instance's exact
live event-delivery work reference, existing grants and resource scopes, all
within the drain deadline. Missing, foreign or completed-delivery references
cannot authorize them or detached workers. New uploads, playback jobs, streams,
receive subscriptions, route registrations and credential issuance remain
closed even with a live reference. Owner-cleanup operations instead permit
owned route unregistration, job cancellation and unsubscription without a work
reference; their grants, scopes and resource ownership checks still apply.

## Typed Discord operations

Construct the ordinary client with `discordv2.NewClient(conn)`. Calls are
context-first and return errors. The SDK includes 153 canonical operations,
43 explicit convenience aliases, and the three route/credential management
operations. Aliases map to canonical RPCs, not additional capabilities.
See `operations.go`, `client_generated.go`, `aliases.go` and the reviewed
[`api-mapping.json`](../tools/protocol/api-mapping.json) for exact signatures and
dispositions. The host supplies Discord API v10/Gateway transport; the SDK does
not expose a raw HTTP escape hatch or live `discordgo.Session`/`State`.

Capabilities are exact operation names, for example
`discord.rest.GuildMemberRoleAdd`, `discord.gateway.RequestGuildMembers`, and
`discord.event.INTERACTION_CREATE`. A namespace prefix is not a wildcard grant.
The host separately checks instance state, actual capability and resource
scopes, trusted relationships, credential purpose/expiry and ownership. Discord
bot permissions, end-user command permissions and Gateway intents still apply;
none replaces a runtime grant.

Complete member-role replacement (`GuildMemberEdit` with a present roles list,
including empty) checks current plus submitted roles and requires protected
guild-wide authority because Discord cannot fence concurrent role assignments
atomically. An absent roles field is unchanged. Granular `GuildMemberRoleAdd`
and `GuildMemberRoleRemove` remain separately scoped operations.

Use the generated safe views and partial/nullable wrappers where the source
SDK would lose presence. Absent, explicit zero/false/empty, list clear and JSON
null are distinct. Interaction and webhook handles hold opaque credential refs,
not raw tokens. Live host objects, voice session credentials and bot tokens do
not cross the module boundary.

Typed snapshots remain authoritative for field presence. When an ordinary
absent/value object maps to a nonpointer SDK struct (for example
`User.PrimaryGuild` or `Activity.Assets`), an absent snapshot field leaves the SDK
field at its zero value; conversion does not invent a present wire object.
Provider null and omission retain the existing ordinary snapshot normalization;
partial/nullable DTOs retain their explicit null distinction. Optional SDK
pointers stay nil, and null collection elements, malformed objects and invalid
nullable/union variants are still rejected.

Outbound message, webhook and component conversion derives value-only string
omission from the reviewed SDK `json:",omitempty"` tags. Empty optional source
strings are omitted; nonempty strings are retained. This includes all four
`WebhookParams` strings (`Content`, `Username`, `AvatarURL`, `ThreadName`), not
only premium-button `SKUID`. Ordinary message snapshots and presence-aware
edit/nullable fields do not use this rule.

Five reviewed value-only numeric fields also follow their source zero-omission
contract, rather than overriding a provider default with a present zero:

| Source field | Meaning when omitted |
| --- | --- |
| `Poll.Duration` | [24 hours](https://docs.discord.com/developers/resources/poll#poll-create-request-object) |
| `Poll.LayoutType` | [DEFAULT layout, value 1](https://docs.discord.com/developers/resources/poll#layout-type) |
| `SelectMenu.MaxValues`, `FileUpload.MaxValues` | [Maximum count defaults to 1](https://docs.discord.com/developers/components/reference) |
| `TextInput.MaxLength` | [Limit unspecified; a present value must be 1–4000](https://docs.discord.com/developers/components/reference#text-input-text-input-structure) |

These are source-adaptation rules, not a blanket `omitempty` encoder. Nonzero
values (including invalid values requiring normal validation), other numeric
zero/false values, pointers, nullable fields and collection presence remain
unchanged. Direct typed wire presence is authoritative: the HTTP encoder does
not silently remove explicitly empty strings or explicit zero values.

Interaction credential scopes retain the authenticated invoking `user_id` from
guild `Member.User` or DM `User`, alongside the source interaction/application
and present guild/channel IDs. Missing or conflicting invoking users fail before
credential issuance. Callback and followup authorization preserve that immutable
user binding; caller-supplied reference metadata cannot replace it.
A returned message's `Author` identifies that message's author, not the invoking
user. Credential-backed postflight checks retain the authenticated invoker while
validating returned author IDs and all other resource relationships; a bot-authored
response does not require replacing or widening the approved invoking user.

Command create, edit, get, list and bulk-overwrite use `ApplicationCommandView`,
including `ApplicationCommandToProto` and `ProtoToApplicationCommand`. Its
`DefaultMemberPermissions` is `*Nullable[int64]`: nil means absent;
`&Nullable[int64]{Null: true}` means explicit null (permission clear on edit);
`&Nullable[int64]{Value: 0}` means explicit administrator-only zero; a nonzero
`Value` retains the exact nonnegative permission mask. HTTP requests emit null,
`"0"` or the decimal mask string respectively; absence omits the key. A normal
Discord response with `default_member_permissions: null` therefore remains a
present null, not an error, an omitted permission or administrator-only zero.
Command options, including recursively nested options, use
`ApplicationCommandOptionView`. Its `MaxValue *float64` and `MaxLength *int`
preserve omission rather than inventing zero limits from SDK value-only fields.
For example, an ordinary string autocomplete option with nil bounds sends neither
`max_value` nor `max_length`; `MaxValue: new(float64(0))` sends an explicit numeric
upper bound of zero, and `MaxLength: new(200)` sends a supported string limit.
Other option fields, choices, context/integration lists and optional default
flags retain their SDK-compatible types. There are no `discordgo.ApplicationCommand`
or `discordgo.ApplicationCommandOption` compatibility overloads: rebuild and
migrate callers to the views rather than collapsing presence.

File readers are not protobuf fields: explicitly stream with
`core.FileClient.Upload` and pass owner-bound `UploadedFileRef` values to typed
Discord operations. Uploads use at most 256 KiB chunks, a separate 500 MiB
storage cap and 30-minute TTL after completion. Discord endpoint limits can be
smaller. Refs can be reused only inside the owning instance and must not be
persisted across restart. Attachment edits specify the complete retained-ID/
new-file-index set; absence and explicit empty clear are different. Helpers do
not silently upload, defer an interaction or retry a mutation.

Optional voice uses `NewVoiceClient(conn)` and bounded playback/receive jobs,
not `OpusSend` channels or module-side Discord sessions. The producer observes
frame and maximum-packet byte credit before reading/encoding each 48 kHz/20 ms
Opus frame, explicitly ends input, and waits for an actual terminal result.
Native DAVE belongs to the separately built host voice artifact; FFmpeg and
download tools belong only inside approved media module images.

## Examples and maintenance

- [`general-bot`](../examples/general-bot/README.md): ordinary management, settings,
  interactions, messages and uploads; builds `bin/test-module` without voice/media prerequisites.
- [`music-bot`](../modules/music-bot/README.md): optional queue/provider
  module with bounded media preparation; builds `bin/chatanium-musicbot`.
- [`audio-player`](../modules/audio-player/README.md): optional bounded
  attachment download/encoding and voice jobs; builds `bin/voice-player-module`.
- [`../proto/README.md`](../proto/README.md): schema/generator inputs and ordering.
- [`../README.md`](../README.md): pinned artifacts, privileged host preparation,
  private secret bindings, runtime configuration and evidence boundaries.

Go is the maintained SDK implementation. Other languages can generate wire
bindings, but must also implement the authenticated sandbox bootstrap,
single-helper transport, lifecycle, presence, credential and error contracts;
generating messages alone is not a supported module implementation. The protocol
remains subject to the linked P0-P6 design/acceptance contracts.
