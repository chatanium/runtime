<h1 align="center">Chatanium v2</h1>
<p align="center">Dynamic Chatbot Runtime</p>

Chatanium is a dynamic chatbot runtime for independently developed bot modules
and online chat providers. Discord is the current optional backend; the v2
protocol keeps module lifecycle, capabilities and isolation backend-neutral.
Ordinary management and message bots do not require music, voice or native DAVE.

Chatanium v2 integrates the module system from
[thirdscam/chatanium-flexmodule](https://github.com/thirdscam/chatanium-flexmodule).
Modules run as independent executables in immutable OCI images under
Docker/runsc (gVisor), communicating over authenticated bidirectional gRPC with
explicitly approved capabilities, resource scopes and finite limits.

**Clean cutover:** the old standard-library `plugin.Open`/`.so` loader, symbol
lookup and direct `discordgo.Session` callback interfaces are removed. There is
no native-plugin fallback, directory-scanning loader, dynamic installer or hot
reload. `hashicorp/go-plugin` remains the authenticated v2 transport inside the
sandbox runner; it is not the removed Go standard-library plugin mechanism.
Modules use typed v2 events/helpers, not the host's Session or bot token.

The independent `modules/MusicBot` checkout is not scanned, loaded or migrated by
the runtime. Its old binary does not become a v2 module by moving or renaming it.
Use the migrated `modules/music-bot` and `modules/audio-player` implementations
and rebuild their approved images. Historical application modules include
[thirdscam/chatanium-musicbot](https://github.com/thirdscam/chatanium-musicbot)
and [thirdscam/chatanium-snowflake](https://github.com/thirdscam/chatanium-snowflake);
those links describe earlier modules, not unchanged-binary compatibility.

## Architecture

![Chatanium Design Architecture](https://github.com/user-attachments/assets/cef88e8c-6689-4a08-8231-ec80d43bbea2)

The original application diagram records Chatanium's multi-provider direction.
It is historical design context, not the current process or security topology:

```text
Operator-approved configuration and immutable OCI images
    |
    +-- privileged flexmodule-supervisor (independent host service)
    |     Docker/runsc, quota, network policy, cleanup/reconciliation
    |
    +-- unprivileged runtime
          core manager, ordered event admission, uploads, credentials
          optional Discord backend (host-only bot token and Gateway)
          optional voice service (separate native-enabled artifact)
              |
              +-- runsc module instances
                    authenticated core-v2 Hook
                    one fixed reverse connection for core/file/backend helpers
                    authenticated storage paths, explicit resource/egress approval
```

Modules must use the authenticated `InitContext.persistent_directory` and
`InitContext.scratch_directory` values, never hardcode mount paths. The current
host constants are `/var/lib/flexmodule/data` and
`/var/lib/flexmodule/scratch`; these implementation locations are not substitutes
for the paths supplied during initialization.

The runtime does not use `PLUGIN_PATH`, launch module binaries directly on the
host, or fall back to runc. go-plugin remains the authenticated AutoMTLS/multiplex
transport inside the sandbox runner; it is not the security boundary by itself.
Each instance permits one reverse-helper transport for its entire lifetime,
using fixed broker ID 1. It is not one connection per helper or backend, and
reconnection/replacement is not authorized. Helper transport failure fails the
instance rather than silently reconnecting with old authority.
Shutdown closes and joins the primary physical yamux session, not just its gRPC
stream, before releasing pinned socket descriptors and requesting host cleanup.
Temporary storage claims remain reserved until the paths are removed and XFS
allocation counters are zero. Cleanup synchronizes once, then observes the XFS
reclamation barrier and exact project counters within the existing cleanup
deadline; deferred inode reclamation is not mistaken for an immediate leak.
Kernel errors or an expired deadline remain cleanup failures and retain claims,
never a successful stop.

Discord helper HTTP requests use fresh HTTP/1 connections with matching
`http/1.1` TLS ALPN, not the default Go transport's inherited `h2` advertisement.
Redirects and automatic mutation replays remain disabled.

Current entry points:

| Path | Responsibility |
|---|---|
| `main.go`, `cmd/` | Root Cobra CLI: `start`, `generate-config`, `new` |
| `internal/app/` | Runtime orchestration, configuration generation and optional backend/voice composition |
| `src/Database/`, `src/Backends/Discord/Database/` | Chatanium-owned in-memory database and host guild/message recording |
| `cmd/flexmodule-supervisor/`, `internal/host/` | Privileged host control and Docker/runsc execution |
| `internal/runtime/`, `internal/runtime/upload/` | Backend-neutral instance lifecycle, grants, admission and file ownership |
| `proto/core-v2/`, `shared/core-v2/` | Lifecycle, configuration, file transfer and authenticated transport |
| `proto/discord-v2/`, `shared/discord-v2/`, `internal/backend/discord/` | Typed Discord domain/events/helpers and host adapter |
| `internal/backend/discord/http/` | Host-only HTTP transport (package `http`, imported as `discordhttp`) |
| `internal/backend/discord/voicejobs/` | Optional bounded voice jobs; native DAVE bridge is supplied by the [maintained SDK patch stack](third_party/discordgo/README.md) |
| `shared/media/opus/` | Module-side bounded FFmpeg/Opus processing, not a core service |
| `examples/general-bot/`, `modules/music-bot/`, `modules/audio-player/` | Ordinary bot example and independent optional media modules |
| `tests/integration/` | Integration runner (`main.go`), `sandbox-policy.py` observer and `fixtures/sandbox/` |
| [Original FlexModule archive](https://github.com/thirdscam/chatanium-flexmodule/tree/main/docs/archive) | Historical voice design/implementation records; not copied into this checkout |

The old v1 wrappers/schema, legacy utility conversion path and experimental
helper-service implementation are removed from the v2 execution path.

Host implementation packages intentionally live under `internal/`; module authors
use public `shared/` and `proto/` packages from
`github.com/thirdscam/chatanium`. Folder names do not change
manifest identity, operator-assigned ModuleIDs, OCI labels or module grants.

### Host application state and output

`internal/app` owns runtime startup, lifecycle and cleanup behind the root Cobra
commands. With Discord enabled, the existing `src/Database` and `src/Guild`
recording handlers attach to the **same** host `discordgo.Session` before it is
opened. There is no second Gateway connection or legacy backend running beside
v2. Trusted host lookups do not impersonate a module principal; modules never
receive the raw Session, bot token or direct DB access.

The host retains the SQLite/sqlc data model and `:memory:` behavior. Its single
connection pool (`MaxOpenConns=1`, `MaxIdleConns=1`) keeps schema creation and
concurrent guild/message callbacks on the same in-memory database. Data is not
newly persisted across restarts. This is distinct from explicitly approved
module-owned persistent storage. Shutdown cancels and joins host recording work
and closes the database along with the backend lifecycle.

Human startup/diagnostic logs go to **stderr**; runtime observations and generated
configuration JSON go to **stdout**. Disk logging under the working directory's
`logs/` is optional. An unavailable working directory or unwritable log location
produces a warning and falls back to stderr instead of preventing startup.
`LOG_MODE=production` is the default; `development` enables verbose logging.
Use canonical absolute operator paths rather than relying on a writable cwd.

## Pinned builds and independent artifacts

The language floor is Go 1.27.0; the compiler is pinned to **Go 1.27.3** in
`.go-version` and `tools/versions.mk`. Supply an actual Go executable through
`BOOTSTRAP_GO`, or install the pinned distribution at `.tools/go/bin/go`.
Version-manager shims are not accepted as compiler executables. The scripts
select the pinned toolchain, neutralize inherited `GOROOT`, and use read-only module files.

`make tools` installs Buf 1.75.0, protoc-gen-go v1.36.12 and
protoc-gen-go-grpc v1.6.2 under `.tools/bin`. From the repository root:

```sh
make tools
make prepare-sdk
make build
make build-media
make buf
make buf-check
```

| Command | Artifact or scope |
|---|---|
| `make prepare-sdk` | Download the pinned upstream DiscordGo module, verify its original checksums and apply the maintained patches; no application/native compilation |
| `make build` | `bin/chatanium`, `bin/flexmodule-supervisor`, `bin/test-module`; Linux/amd64 and CGO=0 by default, no native DAVE or media tools |
| `make build-media` | `bin/chatanium-musicbot`, `bin/voice-player-module`; Go compilation only, no media tool installation |
| `make build-all` | All three local Go modules, including root packages and ordinary/media binaries; native voice is a separate target |
| `make build-native BUILD_JOBS=2` | Independent native C++/ABI/loader/license gate; `.tools/native/prefix` and `.tools/native/bundle`, no application Go compilation or `bin/voice-runtime` publication |
| `make build-voice BUILD_JOBS=2` | `bin/chatanium-voice` plus ancillary `bin/voice-runtime/{lib,licenses,provenance}/`; explicit voice/CGO build |
| `make buf` / `make buf-check` | Transactional owned protobuf publication / non-mutating generation comparison; see [protocol maintenance](proto/README.md) |
| `make build-integration` | `bin/flexmodule-integration` from `tests/integration` and the `internal/app`-package `bin/flexmodule-runtime-return-holder`; CGO=0, no test execution |
| `make build-sandbox` | `bin/sandbox-module` from `tests/integration/fixtures/sandbox` |
| `make check-offline` | 21 focused SDK-preparation tests, Buf schema/generation comparison and bounded ordinary tests in the prepared SDK and all three local Go modules; no separate SDK checkout, live Discord or native build |
| `make clean` | Enumerated ordinary binaries only; no Docker prune or deletion of retained native work |

The three local Go modules are `.`, `modules/music-bot`, and
`modules/audio-player`. All require `github.com/bwmarrin/discordgo`
`v0.29.1-0.20260214123928-f43dd94faaac`, upstream commit
`f43dd94faaacd5b163e9e783f14b5bd8be639fc9`. The root `go.mod` is the version
authority and replaces that module with `./.tools/deps/discordgo`; each nested
module uses `../../.tools/deps/discordgo` and a local Chatanium root
replacement. DiscordGo imports use `github.com/bwmarrin/discordgo`; the public
SDK module path is `github.com/thirdscam/chatanium`. Preparation and pinned
protobuf generation work from this checkout alone; no sibling FlexModule or
DiscordGo checkout is required.

[`tools/sdk.py`](tools/sdk.py) downloads verified upstream source in an isolated
module context and applies these four patches from
[`third_party/discordgo/patches/`](third_party/discordgo/patches/):

1. `0001-toolchain-and-dependencies.patch`
2. `0002-discord-api-and-partial-state.patch`
3. `0003-context-aware-bounded-gateway.patch`
4. `0004-native-dave-voice-transport.patch`

Patch filenames determine lexical application order; there is no `series` file.
The complete stack preserves the reviewed functional SDK, not unmodified
upstream. `Label`, `FileUpload` and `MessageSnapshot` already exist in the pinned
upstream source; they are not local patch additions.
[`third_party/discordgo/upstream.sum`](third_party/discordgo/upstream.sum) is the
sole original-upstream checksum authority. Consumer `go.sum` files are not:
`go mod tidy` prunes the original module's sums when a local replacement is used.

Preparation publishes complete immutable generations under ignored
`.tools/deps/discordgo-generations/`, selected atomically by the stable relative
symlink `.tools/deps/discordgo`. Identical inputs reuse the existing generation
without changing its files; failures preserve the previous tree. Do not edit
prepared source or the alias, mutate a shared Go module cache, or delete older
generations while readers may use them.

Run `make prepare-sdk` before direct Go commands in the root or nested modules.
Repository build, image and offline entry points prepare first, then retain a
shared `.tools/deps/discordgo.lock` lease while compilers or native containers
consume the alias. Preparation uses the exclusive lock; never invoke it while
holding a shared lease. Direct raw Go commands must prepare first and avoid
concurrent dependency preparation; consumers of the stable alias can use the
same shared lease and `tools/sdk.py --verify-only` revalidation sequence.
Read-only validation does not download, write or take a write lock. The
stdlib-only protocol extractor resolves an immutable generation `Dir` and reads
it directly; do not wrap it or preparation commands in a shared lease, which
would deadlock their exclusive preparation.

Compilation and [protocol extraction](proto/README.md#maintain-source-derived-contracts)
use the same prepared source. Provenance records `Path`, `Version`, `Sum`,
`GoModSum`, `PatchSHA256` and `SourceSHA256`; resolver `Dir` points to the
immutable generation and is not portable provenance.

The published SDK `v0.30.0` at commit
`f2d1806d4599ff674163be703c0d62a23d4bb524` remains historical functional-source
evidence, not a consumed module or build prerequisite. Its source repository and
remote tags were not modified by this migration. Publication records and past
live-test evidence do not verify a new build. Public DTO-only consumers can use the pinned upstream DiscordGo module;
Go replacements do not propagate to downstream consumers. Host runtime behavior
requires the maintained patches. Historical external-consumer evidence in the
original repository is not verification of this Chatanium checkout.

Source moves preserve output names: `examples/general-bot` builds
`bin/test-module`, `modules/music-bot` builds `bin/chatanium-musicbot`, and
`modules/audio-player` builds `bin/voice-player-module`.

Native/media artifact builds require Linux/amd64, Docker Engine with BuildKit
supporting `ADD --checksum` and `COPY --chmod`, Python 3.8+, GNU
`readelf`, `ldd`, `timeout`, `flock`, `setsid`, and the target
`/lib64/ld-linux-x86-64.so.2`. Keep the checkout and workspaces below `/home`.
Large source/dependency/compiler/cache trees stay in `.tools/deps`,
`.tools/native` or `.tools/media`, not host `/tmp` or Docker compiler layers.
This repository's [`tools/native/native-lock.json`](tools/native/native-lock.json)
and `tools/media/tool-lock.json` pin compiler bases, package inputs and sources.
Native work, prefixes and bundles remain under `.tools/native`. Builds do not
install host packages or prune/restart Docker.

The optional native bundle uses an EL9 builder and pinned libdave commit
`6396c90aedbb9a6ee117ea9ce1ce9832af6a3375` with
[`third_party/libdave/patches/0001-flexmodule-abi.patch`](third_party/libdave/patches/0001-flexmodule-abi.patch).
This repository owns the native lock, ABI patch, EL9 builder and bundle packaging.
The host prepares the SDK before taking its shared build lease; the native
container reads that prepared source through `/source/.tools/deps/discordgo`,
validates without writes and compares all six provenance fields with the host.
There is no separate `/sdk` mount or SDK-owned native input.
It is a **source-patched fork**, not an upstream libdave release binary.
Publication requires its actual ELF providers, eager relocation and target loader
checks; a distro glibc version alone is not an ABI compatibility guarantee.
The voice executable has RUNPATH `$ORIGIN/voice-runtime/lib`: install
`chatanium-voice` alongside the complete `voice-runtime/` directory, preserving
its `lib/`, `licenses/` and `provenance/` contents and relative layout. The latter
is ancillary data, not another runtime entry point. Do not install just the Go
executable or rename its companion directory. A native build does not prove
encrypted Discord interoperability.

## Create a v2 module

The root CLI exposes `start`, `generate-config` and `new`; use Cobra's
**double-hyphen** long flags. Run `./bin/chatanium --help` or a subcommand's
`--help` for its interface. `new` preserves the interactive name prompt when
`--name` is omitted. It creates source, not a running installation.

From this Chatanium checkout, with the pinned compiler installed as above:

```sh
make prepare-sdk
make build
SDK_CHECKOUT="$PWD"
MODULE_OUTPUT="${MODULE_OUTPUT:?set an absolute new module directory}"
./bin/chatanium new \
  --name ping-bot \
  --output "$MODULE_OUTPUT" \
  --module-path example.com/ping-bot \
  --sdk-path "$SDK_CHECKOUT"

# Use the actual pinned compiler path if it is installed elsewhere.
GO="$SDK_CHECKOUT/.tools/go/bin/go"
(
  cd "$MODULE_OUTPUT"
  env -u GOROOT GOTOOLCHAIN=local "$GO" mod tidy
  env -u GOROOT GOTOOLCHAIN=local "$GO" test ./...
  env -u GOROOT GOTOOLCHAIN=local CGO_ENABLED=0 GOOS=linux GOARCH=amd64 \
    "$GO" build -trimpath -o module .
)
```

`--output` defaults to `modules/<name>`; `--module-path` defaults to
`example.com/<name>`; `--sdk-path` defaults to the current directory and must be
this v2 Chatanium checkout. Use your actual Go module import path before
publishing. The generated `go.mod` explicitly replaces both Chatanium and
DiscordGo with this checkout and its prepared SDK. No published v2 release or
sibling checkout is assumed. If moving the SDK, update both replacements, and
do not race direct builds against SDK preparation. Commit the resolved `go.sum`.

The generated module replies `pong` to a human's `!ping` only in its configured
guild text channel; it ignores DMs, bot messages, other channels and other
commands. The generated **`main_test.go`** exercises INIT/GetStatus at the actual
uint64 Snowflake business boundary, accepting the largest valid ID and refusing
overflow. It is not a live Discord test.

Set real approved `guild_id` and `channel_id` values in private module JSON using
`config.example.json`. Approve resource-free `core.config.read`, Discord major 2,
`discord.event.MESSAGE_CREATE` and
`discord.rest.ChannelMessageSendComplex` at that exact guild/channel. Do not
constrain the send-helper grant to an unknown user/message ID. The manifest's
all-resource requests are ceilings, not approvals. The host bot requires
**guild-message and message-content Gateway intents** (enable privileged message
content in the Discord developer configuration as applicable), plus channel
**View Channel** and **Send Messages** permissions. Runtime grants do not replace
those checks. The generated example needs no voice, uploads, routes or network
egress authority.

Follow the generated README's complete image procedure: build its static
`module` executable, validate the canonical embedded `manifest.json` using this
checkout's `tools/build/manifest`, and build the supplied scratch Dockerfile
with the exact manifest bytes and SHA-256 labels. `make image-module` below
packages the repository's general-bot/sandbox fixtures, **not** arbitrary output
from `new`. Publish the generated image through your approved registry workflow,
obtain its real immutable `registry/repository@sha256:...` RepoDigest, make that
digest available to the supervisor, and follow the approval/configuration flow
below. Copying a binary into `modules/` does not install it; there is no installer
or hot reload.

### Module images

Set these variables to real writable OCI repository/tag names before invoking:

```sh
make image-module MODULE_IMAGE="${MODULE_IMAGE:?set an ordinary module image tag}"
make image-module MODULE_KIND=sandbox \
  MODULE_IMAGE="${SANDBOX_IMAGE:?set a sandbox fixture image tag}"
make image-media \
  MUSIC_IMAGE="${MUSIC_IMAGE:?set a music module image tag}" \
  PLAYER_IMAGE="${PLAYER_IMAGE:?set a player module image tag}" BUILD_JOBS=2
```

Ordinary images are static Go on `scratch`, without FFmpeg, yt-dlp, Deno or
native DAVE. Media images share a pinned tools layer with fixed executables:
`/opt/flexmodule/bin/ffmpeg`, `/opt/flexmodule/bin/ffprobe`,
`/opt/flexmodule/bin/deno`, and the complete
`/opt/flexmodule/yt-dlp/yt-dlp` onedir distribution. No host PATH lookup or runtime
updater is used. DCA is not the v2 playback path.

The host owns module temporary storage: it mounts scratch at
`/var/lib/flexmodule/scratch` and injects `TMPDIR` at bootstrap. Module images
must not declare `TMPDIR`, `FLEXMODULE_PLUGIN`, or any `PLUGIN_*` variable;
the host rejects even matching image defaults before container creation.
The media tools image defaults `HOME` to that scratch mount and `DENO_DIR` to
its `deno` child, never `/scratch`. After authenticated INIT, media subprocesses
explicitly use generated instance-owned scratch/cache children for HOME,
TMPDIR, Deno cache and working directories rather than relying on image defaults.
Builder-only `TMPDIR=/work/tmp` stays in the bind-mounted build workspace;
it is not a permitted module-image runtime environment declaration.

`make image-media` runs the complete build via `tools/build/images.sh media`
and `tools/build/images.py`, including the pinned tool producer. Its completed
tools-image context is `.tools/media/stage`, with payload in `stage/rootfs`;
the tools layer is packaged with `tools/media/Tools.Dockerfile` before both
module images inherit it through `tools/media/Module.Dockerfile`. For an
image-environment-only correction, an operator can reuse a previously completed,
verified staged payload and package it with the current Tools Dockerfile without
recompiling unchanged tools. Do not reuse the stale staged `Dockerfile`;
refresh changed source hashes in `opt/flexmodule/provenance/builder-source-sha256.json`
and the payload inventory `files-sha256.json` under `stage/rootfs` before
publication, retaining the actual tool-build provenance. Rebuild inheriting
module images and record their new image IDs/registry digests; existing images
do not acquire corrected environment declarations retroactively.

Each executable embeds its own canonical `manifest.json`; the builder strictly
parses it and copies the exact bytes into
`org.chatanium.flexmodule.manifest.v2`. The runtime compares the authenticated
module manifest with that image declaration. Declarations are requirements,
**not approvals**. `.tools/images/*-image.json` records local IDs separately from
registry RepoDigests. Publish through your approved registry workflow and use the
actual `registry/repository@sha256:...` RepoDigest in installation config; a local
tag or image ID is not a substitute.

## Prepare a host

Builds do not provision a host. `tools/host/prepare.py` is an explicit EL9 lab
provisioner for rootful Docker **29.5.3**, cgroup v2/systemd, runsc release
`release-20261026.0`, and XFS project quotas. It requires administrator-installed
system tools including `conntrack-tools`, `xfsprogs`, `zstd`, `iptables-nft`,
`iproute`, `util-linux`, `curl`, `shadow-utils` and `systemd`.
Missing dual-stack forwarding or firewall hooks are reported, not silently fixed.

Review the script and install it as root-owned mode 0755 at
`/opt/flexmodule-lab/prepare.py`, below root-owned, non-group/world-writable
directories with no symlink components. Do not execute a user-writable checkout
as root. Supply `/etc/flexmodule-lab/network.json` under the same trust rules.
That operator inventory must contain exactly:

- `ipv4_pool`, `ipv6_pool`: dedicated canonical, noncolliding module CIDRs.
- `resolvers`: actual public numeric resolver addresses.
- `host_public_addresses`: actual host/public/NAT addresses to exclude.
- `internal_prefixes`, `metadata_prefixes`: actual protected destination ranges.
- `inventory_revision`: an explicit finite revision string.

All inventory lists are mandatory and nonempty. Documentation addresses, guessed
public IPs and copied workstation ranges are not deployment inventory.
Set every bound below to an approved positive integer. This command performs
read-only preflight; repeat it with the exact `--apply` flag only to authorize
the documented host mutations:

```sh
sudo /usr/bin/python3 -I /opt/flexmodule-lab/prepare.py \
  --inventory /etc/flexmodule-lab/network.json \
  --max-message-bytes "${SUPERVISOR_MAX_BYTES:?set packet bound}" \
  --max-connections "${SUPERVISOR_MAX_CONNECTIONS:?set connection bound}" \
  --operation-timeout-seconds "${HOST_OPERATION_SECONDS:?set operation bound}" \
  --reconcile-interval-seconds "${HOST_RECONCILE_SECONDS:?set reconciliation interval}" \
  --api-deadline-seconds "${HOST_API_SECONDS:?set Docker API deadline}" \
  --termination-deadline-seconds "${HOST_TERMINATION_SECONDS:?set termination deadline}" \
  --deadline-seconds "${HOST_PREPARE_SECONDS:?set whole-command deadline}"
```

The source enforces each flag's finite range. Apply creates/verifies the dedicated
`flexmodule-runtime` account, a 32 GiB backing XFS image beneath
`/home/flexmodule-lab-storage`, and its `prjquota,nodev,nosuid` mount at
`/var/lib/flexmodule-lab/data`. It writes root-only
`/etc/flexmodule-lab/supervisor.json`, registers the named Docker runtime
`flexmodule-lab-runsc-20261026`, validates the merged Docker config, and uses
SIGHUP rather than restarting Docker. It does not start services, install
packages, change fstab/sysctl/firewall rules, reformat existing data or adopt
permission-mismatched directories. Reapplication requires module networks to be
absent, because collision checks also inspect workload routes.

The mount contains separate `management`, `modules`, `ipc` and `discord`
directories. The Discord ownership directory is runtime-owned mode 0700 and
outside module storage/IPC mounts; do not substitute the root-owned management
directory. Inspect generated UID/GID values rather than assuming numbers.
Install reviewed runtime/supervisor binaries into a root-protected executable
directory, for example `/opt/flexmodule-lab/bin`, before service launch.
Start the supervisor independently, as root, in its own terminal/service:

```sh
sudo /opt/flexmodule-lab/bin/flexmodule-supervisor \
  --config /etc/flexmodule-lab/supervisor.json
```

The runtime must not belong to the Docker group or receive the Docker socket.
It connects only to the supervisor socket, whose lab path is
`/var/lib/flexmodule-lab/data/management/control.sock`. The supervisor owns
cleanup even if the runtime dies. Before each Docker container/network create,
it durably records `SUBMITTED` with a deterministic name bound to the owner
triple. Any create error conservatively retains that record. A later NotFound
does not prove the request never committed: cleanup reports
`CREATE_OUTCOME_UNRESOLVED` / `UNRESOLVED_CREATE` and retains storage, quota and
the installation lease across restart. Reconciliation must first observe the
exact object ID with all ownership labels and persist `OBSERVED`; only subsequent
confirmed absence can release its cleanup obligations. It does not adopt/restart
objects or expose a force-release shortcut. Actual delayed-Docker fault timing
still requires separate exercised evidence.

## Configure and run

`chatanium start` optionally loads `.env` defaults from its working directory
without overriding environment values already provisioned by the operator. A
missing `.env` is allowed; an unreadable or malformed one is an error. There is
no `private.env` autoload or `${...}` interpolation in module JSON.
`generate-config` does not load `.env`. Secret selection remains an explicit
`env:NAME` binding, not implicit use of legacy `DISCORD_TOKEN`, `GUILD_ID` or
`PLUGIN_PATH` settings.
For Discord, configure `backends.discord.major` as `2` and
`secret_sources.bot_token` as `env:FLEXMODULE_DISCORD_BOT_TOKEN`; inject the real
value into the **runtime process only** using your private service environment.
Never put it in config, image labels, argv, module environment or logs.
Provisioned user credentials use explicit purpose/resource/expiry bindings and
opaque refs; the bot token cannot be provisioned to a module.

### Operator inputs

Prepare three separate files before `generate-config`:

1. A valid runtime base JSON with `schema_version: 2`, `modules: []`, and the
   host/backend policy below. It is not the supervisor JSON.
2. Module-scoped JSON matching the chosen [ordinary](examples/general-bot/README.md),
   [music](modules/music-bot/README.md), or
   [player](modules/audio-player/README.md) contract, containing approved real IDs.
3. A strict protobuf-JSON `core-v2.Grants` approval with exact capabilities,
   resource scopes, resource profile and finite limits. Do not copy an image's
   requested `allResources` ceiling into approval to make initialization pass.

All input/output paths must be canonical absolute, non-symlink regular files,
owned by root or the runtime UID, and not group/world writable. The runtime
bounds operator files to 16 MiB. Install the final config so that the dedicated
runtime user can read it; the lab's root-only supervisor-config directory does
not automatically grant runtime access.

The authoritative JSON field names and validation rules are in
[`internal/runtime/config.go`](internal/runtime/config.go) and [`internal/app/discord.go`](internal/app/discord.go):

| Runtime base object | Required policy |
|---|---|
| `host` | Observed `docker_endpoint`, `docker_engine_version`, `runsc_runtime_name`, `runsc_version`, `runsc_sha256`, `management_directory`, `storage_root`, `ipc_root`; `quota_backend` is `xfs-project`. Match the independently prepared supervisor. |
| `host.network` | `firewall_backend` is `iptables`; `ipv4` and `ipv6` true; explicit `resolvers`, `host_public_addresses`, `internal_prefixes`, `infrastructure_prefixes`, `metadata_destinations`. Include actual infrastructure exclusions, not just the module pool. |
| `backends` | `{}` is backendless; only `discord` major 2 is composed by the current executable. No automatic Discord or voice registration. |
| `resource_profiles` | Optional explicit profiles with `cpu_millicores`, `memory_bytes`, `max_pids`, `persistent_bytes`, `scratch_bytes`; all finite and positive, storage in 512-byte multiples. Built-ins: general 0.5 CPU/256 MiB/64 tasks/1 GiB persistent/256 MiB scratch; media 2 CPU/1 GiB/128 tasks/5 GiB persistent/2 GiB scratch. Profiles do not grant internet or voice. |
| `defaults` | Optional positive `startup_deadline`, `drain_deadline`, `event_queue_events`, `event_queue_bytes`; defaults are 30s, 10s, 256 and 32 MiB. |
| `limits` | All fields listed below are required; no missing-to-unlimited fallback. |

`limits` duration strings: `termination_deadline`, `docker_api_deadline`,
`hook_rpc_deadline`, `readiness_poll_interval`, `credential_ref_max_ttl`,
`upload_deadline`. Positive integer bounds: `control_message_max_bytes`,
`config_max_bytes`, `control_rpcs_per_instance`, `credential_refs_per_instance`,
`persistent_inode_limit`, `scratch_inode_limit`, `log_buffer_bytes`,
`log_file_max_bytes`, `log_retained_files`, `upload_records_per_instance`,
`upload_records_per_host`, `upload_file_name_max_bytes`,
`upload_content_type_max_bytes`. Control framing must fit a 256 KiB upload chunk
and metadata; config framing must fit below that control bound. Log workspace
must exceed `3 * control_message_max_bytes + 65536 + 4096 + 256`.
Readiness polling must be shorter than startup; per-instance upload record
capacity cannot exceed the host capacity.

For `backends.discord.config`, supply `application_id`, `bot_user_id`,
`ownership_directory`, numeric `intents`, independent
`gateway_frame_max_bytes` and `gateway_decoded_max_bytes`, duration strings
`credential_ttl`, `interaction_ttl` (at most 15m), `nonce_ttl`, and positive
`nonces_per_instance`, `nonces_per_host`, `nonce_chunks_max`, `routes_per_module`,
`routes_per_host`, `max_routes_per_request`, `max_files_per_request` (at most 10),
`file_max_bytes`, `request_max_bytes`.
Its `http` object requires duration strings `request_deadline`,
`rate_limit_retention` and bounds `json_max_bytes`, `response_max_bytes`,
`header_max_bytes`, `requests_per_instance`, `requests_per_host`,
`rate_limit_buckets`. `presence_owner` and `provisioned_secrets` are optional
explicit policy, not inferred module rights.

Omit `voice` for ordinary bots. The ordinary runtime rejects voice configuration.
For the separate voice artifact, use the exact mandatory voice/transport JSON
fields in [`internal/backend/discord/voicejobs/config.go`](internal/backend/discord/voicejobs/config.go)
and the SDK transport config; those duration fields use numeric nanoseconds, not
the runtime's duration-string encoding. Voice control and packet limits must
match the runtime/transport bounds. No media tool or native dependency belongs in
the ordinary module image.

### Generate an installation

Run the generator as the dedicated runtime user, against the already running
supervisor. Variables below are operator inputs, not sample IDs or digests:

```sh
sudo -u flexmodule-runtime -- /opt/flexmodule-lab/bin/chatanium generate-config \
  --base "${RUNTIME_BASE:?set absolute base JSON path}" \
  --module-config "${MODULE_CONFIG:?set absolute module JSON path}" \
  --approval "${MODULE_APPROVAL:?set absolute Grants JSON path}" \
  --image "${MODULE_REPODIGEST:?set actual immutable registry RepoDigest}" \
  --module-id "${MODULE_ID:?set stable installation identity}" \
  --entrypoint /opt/flexmodule/module \
  --uid "${MODULE_UID:?set approved nonzero module UID}" \
  --gid "${MODULE_GID:?set approved nonzero module GID}" \
  --supervisor-socket /var/lib/flexmodule-lab/data/management/control.sock \
  --supervisor-uid 0 \
  --supervisor-max-bytes "${SUPERVISOR_MAX_BYTES:?use the prepared packet bound}"
```

The exact digest must already exist in the supervisor's local image store.
The generator verifies its strict v2 image manifest, preserves separately supplied
approval, revalidates the resulting installation and writes JSON to stdout.
Capture it into a private staging file, then install it atomically with explicit
ownership/permissions; it never overwrites your config. It currently generates
one module from an empty base. For multiple installations, compose the `modules`
array using the same schema and independent approvals; do not rerun it against a
nonempty base. Optional `--config-revision` and `--approval-revision` record operator
revisions. Provisioned credential bindings require the explicit schema fields;
the generator does not invent them.

With a real token already exported in the invoking administrator's private
environment, an ordinary Discord runtime can be started as:

```sh
sudo --preserve-env=FLEXMODULE_DISCORD_BOT_TOKEN -u flexmodule-runtime -- \
  /opt/flexmodule-lab/bin/chatanium start \
  --config "${RUNTIME_CONFIG:?set absolute installed runtime JSON path}" \
  --supervisor-socket /var/lib/flexmodule-lab/data/management/control.sock \
  --supervisor-uid 0 \
  --supervisor-max-bytes "${SUPERVISOR_MAX_BYTES:?use the prepared packet bound}"
```

For backendless operation omit secret preservation; for optional voice use the
installed `chatanium-voice start` command with its adjacent
`voice-runtime/` directory instead. `SIGINT`/`SIGTERM`
drain instances before backend/upload cleanup. `--duration` provides an optional
finite run interval, not interactive acceptance proof. `make run` exposes the
same runtime flags through `CONFIG`, `SUPERVISOR_SOCKET`, `SUPERVISOR_UID` and
`SUPERVISOR_MAX_BYTES`, but does not start/provision the supervisor.

## Generic modules, scopes and validation boundaries

[`general-bot`](examples/general-bot/README.md) demonstrates ordinary slash commands,
forms, settings, guild/DM message events, streaming attachments, and explicitly
approved member/role/channel moderation and audit operations.
[`music-bot`](modules/music-bot/README.md) and
[`audio-player`](modules/audio-player/README.md) are separate optional
media examples, not the definition of a FlexModule module.

Capabilities, actual resource scopes, Discord bot permissions, user command
permissions and Gateway intents are separate checks. Required capability refusal
prevents activation; optional refusal disables only the corresponding feature
when the module contract permits it. The ordinary basic path needs no privileged
intent, internet grant or voice capability. Module IDs remain stable across runs;
instance IDs, credentials and upload refs do not.

For `GuildMemberEdit`, an absent `roles` field preserves assignments. A present
roles list, including an explicit empty list, replaces the full set: the backend
checks existing and submitted roles and requires separately protected guild-wide
authority because Discord offers no atomic assignment-version precondition.
This is not an atomic snapshot guarantee. Use `GuildMemberRoleAdd`/`Remove` for
granular approved role changes; those operations do not inherit the full
replacement requirement.

These historical proposals live in the original FlexModule repository, not in
this checkout, and retain their original review metadata and audits:
[P0 build baseline](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-0-build-and-dependency-baseline.md),
[P1 protocols](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-1-protocol-contracts.md),
[P2 conversions](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-2-domain-conversions.md),
[P3 Discord](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-3-discord-backend.md),
[P4 runtime/isolation](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-4-runtime-and-isolation.md),
[P5 voice](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-5-voice-jobs.md),
[P6 examples/acceptance](https://github.com/thirdscam/chatanium-flexmodule/blob/main/docs/proposals/flexmodule-6-examples-and-validation.md).
Their pre-cutover descriptions of "current v1" are historical motivation, not
instructions to use removed sources. This README describes current source
interfaces, not a claim that every proposal acceptance case has passed.

The bounded validation entry points are:

```sh
make check-offline CHECK_DEADLINE=1800s TEST_TIMEOUT=120s
make check-sandbox CONFIG="${RUNTIME_CONFIG:?}" \
  SUPERVISOR_SOCKET="${SUPERVISOR_SOCKET:?}" SUPERVISOR_UID="${SUPERVISOR_UID:?}" \
  SUPERVISOR_MAX_BYTES="${SUPERVISOR_MAX_BYTES:?}" CHECK_DEADLINE=120s OBSERVE=15s
make smoke-discord CONFIG="${RUNTIME_CONFIG:?}" \
  SUPERVISOR_SOCKET="${SUPERVISOR_SOCKET:?}" SUPERVISOR_UID="${SUPERVISOR_UID:?}" \
  SUPERVISOR_MAX_BYTES="${SUPERVISOR_MAX_BYTES:?}" CHECK_DEADLINE=180s OBSERVE=60s
make smoke-voice CONFIG="${RUNTIME_CONFIG:?}" \
  SUPERVISOR_SOCKET="${SUPERVISOR_SOCKET:?}" SUPERVISOR_UID="${SUPERVISOR_UID:?}" \
  SUPERVISOR_MAX_BYTES="${SUPERVISOR_MAX_BYTES:?}" CHECK_DEADLINE=180s OBSERVE=60s
```

Scenario configs must match the selected ordinary/sandbox/media image and actual
approvals. `smoke-voice` needs the separately built voice artifact.
`tests/integration` launches the real runtime through the real supervisor, never
an unsandboxed module fallback. Its per-case JSON distinguishes observations from
`NOT_RUN`; activation alone does not prove moderation, attachment delivery,
network isolation or encrypted audio. Missing full sandbox-policy or interactive
Discord/participant proof remains nonpassing, not an invented success.

This documentation does not assert sandbox-runtime, live Discord or encrypted
voice end-to-end success. Live acceptance requires separately recorded
operator-approved browser actions and, for voice, actual encrypted playback and
receive observations with participants.

## Licensing, origin and redistribution

Existing Chatanium files retain the [MIT license](LICENSE). The module-system
transplant comes from
[thirdscam/chatanium-flexmodule](https://github.com/thirdscam/chatanium-flexmodule),
whose original root license is MPL-2.0, preserved verbatim in
[`LICENSE.flexmodule`](LICENSE.flexmodule). The existing root `LICENSE` is not
replaced. This is preservation of notices and existing terms, **not relicensing**.

FlexModule-derived files in `proto/`, `shared/`,
`internal/{runtime,host,backend,app}/`, `cmd/flexmodule-supervisor/`, `tools/`,
`tests/integration/`, `examples/`, `modules/audio-player/`, and the copied
`Makefile` and maintained patch work retain the original MPL terms unless more
specific existing notices apply. In particular,
[`modules/music-bot/LICENSE`](modules/music-bot/LICENSE) is independently MIT;
it is not made MPL by residing beside those files. Preserve original copyright,
source provenance and file/dependency notices when modifying or redistributing
these components, including applicable MPL source-availability obligations.

Upstream dependencies retain their own licenses. The maintained
[DiscordGo patch stack](third_party/discordgo/README.md#licensing-and-attribution)
retains upstream BSD-style terms and Bruce Marriner's notice; it is not
relicensed by the transplant. The
[libdave ABI patch](third_party/libdave/README.md#licensing-and-attribution)
preserves libdave's MIT/Discord notice and separate dependency terms. The native
build collects installed vcpkg and system-library notices as well as native
provenance; distribute `bin/voice-runtime/licenses/` and
`bin/voice-runtime/provenance/` with the executable and libraries. Keep exact
source/patch/build records and meet the applicable dependencies' redistribution
and source requirements, not just the root application license.

Media images likewise retain their FFmpeg, Opus, yt-dlp, Deno, Python/system
library and transitive dependency notices under `/opt/flexmodule/licenses`,
with lock, configure and source/asset records under
`/opt/flexmodule/provenance`. FFmpeg's actual configured build and enabled
components determine its applicable terms; do not label the entire media image
MIT or discard notices/source records because the module itself has an MIT
license. Native or media build success is not a blanket legal-compliance or live
Discord acceptance claim.

## Historical operational context

The original repository's
[local Discord browser debugging guide](https://github.com/thirdscam/chatanium-flexmodule#local-discord-browser-debugging)
documents a separate workstation-specific browser container/CDP setup. It is
historical operational context, not a provisioned service or prerequisite supplied
by this checkout. Keep browser credentials, tokens, private messages and network
payloads out of repository artifacts; never expose a signed-in browser's CDP
endpoint publicly.
