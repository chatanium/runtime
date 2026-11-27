<h1 align="center">Chatanium v2</h1>
<p align="center">Dynamic Chatbot Runtime</p>

Chatanium is a dynamic chatbot runtime for independently developed bot modules
and online chat providers. Discord is the current optional backend; the v2
protocol keeps module lifecycle, capabilities and isolation backend-neutral.
Ordinary management and message bots do not require music, voice or native DAVE.

Chatanium v2 integrates the module system from
[Chatanium FlexModule](https://github.com/chatanium/flexmodule).
Modules run as independent executables in immutable OCI images under the bundled
original `rungv` (gVisor), with authenticated bidirectional gRPC, explicitly
approved capabilities, resource scopes and finite limits. Docker is build-only.

**Clean cutover:** the old standard-library `plugin.Open`/`.so` loader, symbol
lookup and direct `discordgo.Session` callback interfaces are removed. There is
no native-plugin fallback, directory-scanning loader, dynamic installer or
automatic production hot reload. Development-only image replacement requires
explicit opt-in; `hashicorp/go-plugin` remains the authenticated v2 transport
inside the sandbox runner, not the removed Go standard-library plugin mechanism.
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
    +-- portable foreground supervisor (ordinary installation-owner account)
    |     verified local bundle and image generations, SQLite admission/cleanup ledger
    |     one managed GVX engine per instance; authenticated gvx-ctrl/2
    +-- unprivileged bundled worker
          core manager, ordered event admission, uploads, credentials
          optional Discord backend (host-only bot token and Gateway)
          native voice only if the target bundle advertises it
              |
              +-- original rungv -> trusted guest bridge -> nonroot module
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
Each module has one persistent ext4lite image and each instance has one ephemeral
image shared by scratch and `/tmp`. Limits are logical image maxima, not host
reservations or guaranteed writable bytes. A slot remains charged until native
exit and scratch removal are confirmed; a lost control connection is not proof.

Discord helper HTTP requests use fresh HTTP/1 connections with matching
`http/1.1` TLS ALPN, not the default Go transport's inherited `h2` advertisement.
Redirects and automatic mutation replays remain disabled.

Current entry points:

| Path | Responsibility |
|---|---|
| `main.go`, `cmd/`, `internal/portable/install/` | User-local doctor, initialization, review, foreground start/stop, offline update, uninstall and purge |
| `internal/app/`, `cmd/chatanium-worker/` | Separately compiled nonroot worker, optional backend/voice composition |
| `internal/configgen/` | Configuration generation from explicitly prepared image records |
| `internal/portable/{engine,process,service,session,sandbox,images,store}/` | Native child lifetime, authenticated controls, guest grants, verified images and the installation ledger |
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
`.go-version` and `tools/versions.mk`. Build scripts discover Go at
`.tools/go/bin/go`, on your `PATH`, or through `goenv` without executing its
shim. Set `BOOTSTRAP_GO` only to override discovery with an absolute path to a
Go executable. The scripts still select the pinned toolchain, neutralize
inherited `GOROOT`, and use read-only module files.

Portable builds find GitHub CLI (`gh`) on your `PATH` to verify the bundled GVX
release. Only a root-owned executable with a protected installation path is
accepted. Set `TRUSTED_GH` only to select a different trusted absolute path.
Neither Go nor `gh` is required on a host that only runs the built launcher.

`make build-runtime` logs three stages: toolchain and SDK preparation, pinned
GVX verification, and launcher build and packaging. Interactive terminals show
color and a single updating build-status line. Set `NO_COLOR=1` to disable
colors. CI and redirected output use plain stage lines.

`make tools` installs Buf 1.75.0, protoc-gen-go v1.36.12 and
protoc-gen-go-grpc v1.6.2 under `.tools/bin`. From the repository root:

```sh
make tools
make prepare-sdk
make build
make buf
make buf-check
```

The host database bindings in `src/Database/Internal/` are checked in, so an
ordinary build or startup does not require sqlc or leftover generated files.
After editing `database/schema.sql` or `database/query.sql`, regenerate with
**sqlc v1.30.0**:

```sh
sqlc version # v1.30.0
make sqlc
```

Commit the SQL changes together with all three generated Go files
(`db.go`, `models.go`, `query.sql.go`). SQL generation is independent of
`make buf` and `make buf-check`.

| Command | Artifact or scope |
|---|---|
| `make prepare-sdk` | Download the pinned upstream DiscordGo module, verify its original checksums and apply the maintained patches; no application/native compilation |
| `make list-module` | Display detailed manifest blocks with name/version, author, description, backend protocols and grouped capability names; no Go/native/SDK preparation, module build or runtime query |
| `make build-runtime GOOS=linux GOARCH=amd64` | Build the offline portable launcher, target-matched original GVX and worker, Linux guest bridge/preparer and their provenance |
| `make build-runtime GOOS=windows GOARCH=arm64` | Cross-build a Windows arm64 artifact on the Linux build host; this is not a WHPX execution test |
| `make build` | Build the portable runtime plus direct v2 module directories under `modules/` |
| `make build-module music-bot` | Build only `modules/music-bot` into `bin/modules/music-bot/module`; any module folder name works without editing the Makefile |
| `make build-module examples/general-bot` | Explicitly build the root-module example into `bin/examples/general-bot/module` |
| `make build-native BUILD_JOBS=2` | Independent native C++/ABI/loader/license gate; `.tools/native/prefix` and `.tools/native/bundle`, no application Go compilation or `bin/voice-runtime` publication |
| `make buf` / `make buf-check` | Transactional owned protobuf publication / non-mutating generation comparison; see [protocol maintenance](proto/README.md) |
| `make build-integration` | `bin/flexmodule-integration` from `tests/integration`; CGO=0, no runtime/test execution |
| `make build-module tests/integration/fixtures/sandbox` | Explicitly build the backendless integration fixture into `bin/tests/integration/fixtures/sandbox/module` |
| `make check-offline` | Focused SDK-preparation tests, Buf schema/generation comparison and bounded ordinary tests in the prepared SDK, root and discovered local Go modules; no live Discord or native build |
| `make clean` | Owned runtime/integration binaries and directory-derived module outputs only; no native bundle deletion or Docker prune |

Portable bundles currently have no native voice closure. `doctor` reports the
capability of the embedded bundle, not the capabilities of another target or an
old installation. The native/media build instructions below concern those
separate artifacts, not portable installation prerequisites.

Module discovery uses each direct `modules/<name>/manifest.json`, not a fixed
module list. Symlinks and non-v2 entries such as the old `modules/MusicBot`
checkout are not discovered. Examples and integration fixtures outside
`modules/` are built only when selected explicitly. A selected directory uses
its nearest enclosing `go.mod`, so both independent modules and packages in the
root Go module work. The current independent modules require `github.com/bwmarrin/discordgo`
`v0.29.1-0.20260214123928-f43dd94faaac`, upstream commit
`f43dd94faaacd5b163e9e783f14b5bd8be639fc9`. The root `go.mod` is the version
authority and replaces that module with `./.tools/deps/discordgo`; each nested
module uses `../../.tools/deps/discordgo` and a local Chatanium root
replacement. DiscordGo imports use `github.com/bwmarrin/discordgo`; the public
SDK module path is `github.com/thirdscam/chatanium`. Preparation and pinned
protobuf generation work from this checkout alone; no sibling FlexModule or
DiscordGo checkout is required.

Each manifest may set the optional `description` field to explain its module's
purpose. `make list-module` uses the same `modules/` discovery as `make build`
and displays backend protocol requirements and requested capability names grouped
by Core and backend, with required/optional totals. `Activated` is `N/A` because
this offline listing does not query live runtime state. The footer's "installed
locally" total counts discovered source directories, not configured, approved or
running runtime installations. Capability requests are not permission grants.
Update the description in the manifest rather than maintaining a separate
module catalog. Missing descriptions are shown explicitly. Changing an embedded
manifest still requires rebuilding the module executable and OCI image together.

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

Module outputs mirror their repository-relative source directory:
`<directory>` builds `bin/<directory>/module`. Adding a module under
`modules/` needs no new target or executable-name mapping. Building a module
does not install or activate it; OCI images and operator approvals remain separate.

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

The default native runtime bundle uses an EL9 builder and pinned libdave commit
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
The separately compiled worker resolves native voice libraries from
`$ORIGIN/voice-runtime/lib`. The static outer launcher embeds that worker and the
complete native/helper closure, then verifies and publishes immutable digest
generations during approved initialization. Install only the externally verified
`bin/chatanium`; do not separately install a worker or companion voice directory.
Neither worker nor helpers import `internal/releasepayload`, preventing recursive
embedding. Native build success does not prove encrypted Discord interoperability.

## Create a v2 module

The root CLI exposes lifecycle commands plus `generate-config` and `new`; use
Cobra's **double-hyphen** long flags. Run `./bin/chatanium --help` or a subcommand's
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
obtain its real immutable `registry/repository@sha256:...` RepoDigest, then prepare
that digest through explicit `chatanium prepare-image` and the approval flow below.
Copying a binary into `modules/` does not install it. There is no implicit
production hot reload; development reload remains a separate opt-in path.

### Module images

Set these variables to real writable OCI repository/tag names before invoking:

```sh
make image-module MODULE=examples/general-bot \
  MODULE_IMAGE="${MODULE_IMAGE:?set an ordinary module image tag}"
make image-module MODULE=tests/integration/fixtures/sandbox \
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

## Run a portable installation

Chatanium uses one installation in `chatanium/runtime` under your user data
directory. On Linux this is `${XDG_DATA_HOME:-$HOME/.local/share}/chatanium/runtime`;
on macOS it is `~/Library/Application Support/chatanium/runtime`; on Windows it is
`chatanium\runtime` under LocalAppData. All portable commands use that same
location. `init` creates an internal identity for the ledger and backups;
you do not name the installation. Module IDs still distinguish your modules.
Older installations under `chatanium/portable-v2/<name>` stay untouched. Use
their original launcher to manage them; the new launcher does not migrate them.

Verify the **outer launcher** against your release publisher's independently
trusted provenance before running it. Its embedded GVX is pinned to
[`v0.22.10002026111600`](https://github.com/gfire-sigs/gvx/releases/tag/v0.22.10002026111600);
pulling `latest` or installing a system container engine is not part of setup.

Run `doctor` from the same user account that will own the
installation. `doctor` is read-only; it distinguishes authenticated bundle
metadata from the installed files. It verifies the embedded bundle manifest
first. If the installation is `INITIALIZING` or `READY` and the digests match, it checks
the exact installed files without taking a lock, opening the ledger, or starting
the engine. `installed_bundle_verification` reports `VERIFIED` on success or
`FAILED` with a nonzero exit. `DIFFERENT_LAUNCHER` means the bundle digests
differ and `doctor` did not check the installed files. Other installation
states report `NOT_APPLICABLE`. The field is absent if no installation exists.

Target backends are Linux amd64/arm64 `systrap`, macOS arm64 `hvf`, and Windows
amd64/arm64 `whpx`. WHPX must already be enabled. The installer does not enable
a hypervisor, create accounts, run a service, mount host volumes or alter host
cgroups, routing or firewall rules.

Run `./chatanium serve` to start. On first use it shows the installation location
and disk limit. Answer `y` to set up and start the foreground worker. With no
modules it waits without launching a container. Later runs reuse the existing
configuration without asking again.

Interactive status lines show the invoked command and a color-coded status,
such as `[ SERVE ] [READY]` or `[ DOCTOR ] [INFO]`. `serve` shows when the
runtime is ready, any module state changes, and when shutdown finishes.
Use `NO_COLOR=1` for the same layout without color. Redirected stdout and CI
keep the existing JSON (newline-delimited events for `serve`). Use `--json`
to request that format in a terminal. `generate-config` and `inspect-config`
always emit JSON documents on stdout.

```sh
# To configure and start a first module from an offline OCI archive instead:
./chatanium serve \
  --source-kind oci-archive --source "$PWD/module.tar" --digest "$ARCHIVE_SHA256" \
  --module-id demo --module-config "$PWD/module.json" --approval "$PWD/grants.json"
# In another terminal, using the same account:
./chatanium stop
```

`ARCHIVE_SHA256` is the trusted `sha256:…` of the whole archive. The
`--approval` file proposes grants; review the module and answer `y` when prompted.
Use `--json-approvals` for complete approval plans. For `serve` and `init`,
this switches setup prompts to exact digests; `reset` always asks `y/N` before
deletion. Standalone `prepare-image`, `configure`, `update` and `purge` always
require exact digests, even when showing a terminal summary. Use repeatable
`--approve` values in prompt order to supply those digests from a script.
To stage an installation or add another module separately:

1. Run `init` instead of `serve` to set up an installation without starting it.
   Inspect the location and disk budget, then answer `y`.
2. `prepare-image` accepts a digest-pinned registry source or an explicitly
   selected OCI archive. Parsing and compilation take place in a separate,
   networkless guest. Images must declare
   `org.chatanium.flexmodule.resources.v2=portable-v2` in addition to their
   core-v2 manifest. Rebuild old images; do not reuse their old approvals.
3. `generate-config` binds the prepared generation to a module, UID/GID,
   resource limits and network grant. `configure` requires the matching module
   `ReviewDigest` before activation. The guest sees its approved PID, RAM and
   CPU limits; these are not constraints on the host worker's RSS or threads.
4. `serve` runs the worker and modules in the foreground.
   `stop` fences new launches before waiting for exit.
   `NONE` has no external networking. `PUBLIC_INTERNET` starts denied and opens
   the reviewed GVX NAT policy only after module authentication and grant checks.
5. Stop before `update` or `uninstall`. Uninstall removes installed code, not
   module data. `purge` lists what it will delete and needs a fresh approval.
   The downloaded executable and shared parent directory are not purge targets.

Running `init` (alias `reset`) on a stopped installation shows what will be
deleted and where it will be recreated. Answer `y` to erase its configuration,
cached images, persistent module data and backups, then create a fresh
installation. The default is **no**: an empty answer, `n` or closed stdin keeps
the existing installation. `serve` never performs a reset. The downloaded
executable and older named installations are outside the deletion scope.

**Restoring a stopped update backup after copying it to another filesystem:**
restore only the listed members (including `config.json`) to a fresh private
installation at the original approved path, using the matching verified code.
Keep the cache read-only and `app/discord`, `app/uploads` and `ipc` owner-only.
Keep the original backup elsewhere; never overlay a live installation.
Copy `backups/B/inventory.json` to `restore-inventory.json` in that installation.
Use the digest you saved independently from the original backup, not a digest
calculated from the copy you are attempting to trust:

```sh
./chatanium bind-restored-volumes \
  --backup-id "$BACKUP_ID" --receipt-digest "$TRUSTED_INVENTORY_SHA256"
```

This is not an image importer. It verifies the restored snapshot and volume
contents before binding their new native file identities. The exact command
can be retried before the first activation. The receipt and config are retained;
this command cannot rebind volumes from an ordinary installation.

No raw ext4 image import: GVX opens an existing volume before host lockdown.
Only this installation's recorded volume with the expected native file
identity and maximum length may be reopened. Details and upstream source:
[portable-v2 design](docs/proposal/CHAT-1.md).

<details>
<summary>Legacy Linux administrator installation (v1 launcher only)</summary>

The following runbooks describe installations made by the older root launcher.
Use that original binary to manage them. Do not run their privileged setup
commands for a portable installation; portable-v2 never migrates or removes v1.

## Prepare a host

The distribution is one static Linux/amd64 launcher. It contains original rungv
`v0.16.10002026110900` at source commit
`a9bfd06c2c07a16e76972ff43379e0ebe0d4223a`, static product helpers, a separate
native-default worker and pinned EL9 XFS/network/shadow-utils closures. Runtime
operation requires no Docker, containerd, runsc installation or engine daemon.
Build-time Docker remains isolated from runtime authority.

Authenticate a download **before executing it**, using an independently trusted
GitHub CLI and approved release tag and source commit:

```sh
gh attestation verify ./chatanium-linux-amd64 \
  --repo chatanium/runtime \
  --signer-workflow chatanium/runtime/.github/workflows/release.yml \
  --source-ref "refs/tags/${RELEASE_TAG:?set approved release tag}" \
  --source-digest "${RELEASE_COMMIT:?set approved exact source commit}" \
  --deny-self-hosted-runners
```

The canonical GitHub repository ID is `695180706`, owner ID `253326933`; verify
those identities as well, since repository names alone can be reused. A local
unsigned build, embedded checksums or a checksum downloaded beside the binary
does not establish this initial trust. The hosted release workflow creates the
product artifact attestation; rungv's upstream attestation is a separate trust
check, not authentication of the Chatanium launcher.

```sh
./chatanium-linux-amd64 doctor
sudo install -o root -g root -m 0755 ./chatanium-linux-amd64 /usr/local/bin/chatanium
sudo /usr/local/bin/chatanium init
sudo /usr/local/bin/chatanium start --foreground \
  --installation-id "${INSTALLATION_ID:?use the approved product installation ID}"
```

`doctor` is passive even as root: no extraction, helper execution, mounts or
units. It distinguishes unsupported, unknown and privileged-check-needed facts.
The initial supported profile requires CPU amd64-v2, systemd 252 features,
cgroup-v2 controllers, Landlock, namespaces, seccomp, pidfd/openat2 and approved
XFS/loop/mount/network privileges. Preparation additionally requires PID1's
`PrivateUsers=true` service boundary, native USER-namespace owner/parent/map
inspection and thread-synchronized seccomp. A systemd property or kernel version
alone proves none of these; an unsupported or mismatched native boundary fails
before target work. Root and PID1 remain trusted. Runtime operation needs no
Docker daemon; build-time Docker is separate.

Bare `init` derives and displays a bounded plan and requires its exact PlanDigest
before preparing anything; each module also requires its own exact ReviewDigest.
It reviews paths, three dedicated identities, protected secrets, finite storage
budgets, image sources and each module's separate grants. `--draft PATH` supplies
protected choices; `--installation-id ID` resumes an existing initialization.
It records PROVISIONING and per-object intent before mutation, never formats
existing data, and reaches READY only after temporary services and mounts settle.
It does not install packages, alter Docker/fstab/global sysctl, register a permanent service,
or silently adopt old Docker state. Dedicated app/sandbox/preparer identities
must have no unexpected NSS groups: an empty systemd SupplementaryGroups array
does not clear account database memberships.

The manager owns the installation lease and lifecycle journal. systemd is the
sole cgroup writer, including FD-passed transient services; its v252 CPU quota
property is `CPUQuotaPerSecUSec`, not `CPUQuotaUSecPerSec`. Uncertain submission
retains claims until authoritative settlement. Owned transient services use both
`AddRef=true` and `CollectMode=inactive-or-failed`: default failed-unit retention
can otherwise keep PID1 stdio open after Unref. Persist the complete terminal
observation first, then Unref, then prove actual unit/job/stdio/process/mount
settlement before quota reclamation. There is no ResetFailed workaround.
Missing native terminal status never becomes exit zero: Wait remains UNKNOWN.
Cleanup may separately use journaled absence evidence only for an exact previously
OBSERVED invocation, after complete job/unit/PID/cgroup/task and FD/namespace/pipe/data
reference absence is proved. SUBMITTED-only uncertainty still requires
authoritative rejection or a boot fence; it cannot use this absence path.

`stop` commits desired STOPPED before drain. Optional `service install --now`
creates explicit RUNNING intent; service restart respects STOPPED. `uninstall`
removes owned code/unit only and preserves data/config/secrets/accounts/source
and recovery records. `purge --installation-id ID` derives its current owned
scope and requires the displayed exact PlanDigest before destruction, after
cleanup proof. Execute `update --installation-id ID` from the new independently
verified, protected launcher and approve its exact current-state PlanDigest.
Update preserves source, hostfs metadata, compatible state and referenced
bundle/cache generations; binary rollback is not data rollback.

Full purge explicitly retains the shared `/var/lib/chatanium/.management.lock`:
a root-owned mode-0600 coordination marker that must never be replaced or
unlinked, including for NONE installations. This is approved shared residue,
not a promise of an empty host. Per-installation `.purge-terminal-<ID>.json`
receipts and `.purge-terminal-<ID>-<TxnID>-<Step>.next` stages in that shared
directory are temporary; remove them only after durable full completion.

Terminal finalization must remain resumable after canonical SQLite is gone.
Only the exact root-validated terminal receipt may continue its original
approval/digest/scope and finite remaining observed control/ancestor removals.
It cannot recreate helpers, data, mounts or the database, or admit ordinary
lifecycle work. Identity mismatches or reappearance of completed targets fail
closed; missing SQLite without that exact authority is not purge success.

The metadata filesystem must support anonymous `O_TMPFILE` publication,
`linkat` no-replace publication, `RENAME_EXCHANGE`, and file/directory `fsync`.
Two actual approved preflight probes must establish publication/exchange
support and durable probe absence **before any selected payload, account or
canonical-helper deletion**, not merely before SQLite removal. Unsupported
filesystems fail closed, without named partial-write fallback, OS/package
changes or weakened cleanup proof.


PUBLIC initialization explicitly approves and journals the shared host-wide
`/var/lib/chatanium/network-ipam` anchor and lock. Per-installation purge removes
only its own allocations and preserves that shared anchor/lock and needed parent:
unlinking a shared lock could split lock ownership or race other installations.
NONE creates no network-IPAM infrastructure; it still retains the shared
management lock above. Neither anchor implies a surviving unit, rule or mount,
and purge is not byte-for-byte host restoration.

Namespace handles are owned bind mounts beneath the installed `RunRoot/netns`.
The runtime does not use `ip netns add/delete` or change global `/run/netns`
self-bind/propagation state. The preserved shared IPAM anchor is only a directory
and lock file, not a retained namespace mount.
Root network helper services explicitly use PrivateMounts and ProtectControlGroups
without CAP_SYS_ADMIN or `ip netns exec`; the product owns native namespace creation.

## Configure and run

The launcher never autoloads `.env` or inherits ambient PATH, loader, proxy or
GVX_DEBUG_LOG into privileged helpers. Secret selection is an explicit `env:NAME`
binding or approved protected secret file, not legacy DISCORD_TOKEN/GUILD_ID/
PLUGIN_PATH defaults. Only selected values go to the nonroot worker over private
bounded control input; no dotenv interpolation is performed.
For Discord, configure `backends.discord.major` as `2` and
`secret_sources.bot_token` as `env:FLEXMODULE_DISCORD_BOT_TOKEN`; inject the real
value into the **runtime process only** using your private service environment.
Never put it in config, image labels, argv, module environment or logs.
Provisioned user credentials use explicit purpose/resource/expiry bindings and
opaque refs; the bot token cannot be provisioned to a module.

### Operator inputs

`generate-config --installation-id ID` passively reads the committed installed
base and inspected image binding; it does not create a runtime epoch. Prepare
two separate protected operator files:

1. Module-scoped JSON matching the chosen [ordinary](examples/general-bot/README.md),
   [music](modules/music-bot/README.md), or
   [player](modules/audio-player/README.md) contract, containing approved real IDs.
2. A strict protobuf-JSON `core-v2.Grants` approval with exact capabilities,
   resource scopes, resource profile and finite limits. Do not copy an image's
   requested `allResources` ceiling into approval to make initialization pass.

Input/output paths must be canonical absolute, non-symlink regular files in
protected directories. Operator files are bounded to 16 MiB. Generate a new
root-owned mode-0600 candidate, then use `configure --config PATH` to inspect and
review its stopped installation plan and each actual module grant. Only that
explicit commit changes installed configuration; stdout generation never does.
Installed config remains root:root 0600 and reaches the worker through private
INIT, not filesystem access. Workers cannot read the lifecycle journal.
Advanced `--base PATH` accepts a separately protected runtime base; it is not
required for the normal installed-base workflow.

The authoritative JSON field names and validation rules are in
[`internal/runtime/config.go`](internal/runtime/config.go) and [`internal/app/discord.go`](internal/app/discord.go):

| Runtime base object | Required policy |
|---|---|
| `host` | Installed `runtime_installation_id`, `bundle_digest`, owned management/storage/IPC paths and `quota_backend: xfs-project`; no Docker endpoint/version/runsc fields |
| `host.network` | Explicit `profile`: NONE, PUBLIC-v4 or PUBLIC-dual. NONE has no route/pool/uplink/source/resolver/inventory fields. PUBLIC requires matching family flags, canonical `ipv4_pool` and optional `ipv6_pool`, `inventory_revision`, `uplink4/source4` and optional `uplink6/source6`, family-compatible resolvers and all host/infrastructure/metadata exclusions. No family downgrade. |
| `backends` | `{}` is backendless; only `discord` major 2 is composed by the current executable. No automatic Discord or voice registration. |
| `resource_profiles` | Optional explicit profiles with `cpu_millicores`, `memory_bytes`, `max_pids`, `persistent_bytes`, `scratch_bytes`; all finite and positive, storage in 512-byte multiples. Built-ins: general 0.5 CPU/256 MiB/64 tasks/1 GiB persistent/256 MiB scratch; media 2 CPU/1 GiB/128 tasks/5 GiB persistent/2 GiB scratch. Profiles do not grant internet or voice. |
| `defaults` | Optional positive `startup_deadline`, `drain_deadline`, `event_queue_events`, `event_queue_bytes`; defaults are 30s, 10s, 256 and 32 MiB. |
| `limits` | All fields listed below are required; no missing-to-unlimited fallback. |

`limits` duration strings: `termination_deadline`, `host_operation_deadline`,
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

Omit `voice` for ordinary bots. A DISABLE_VOICE build rejects voice configuration.
For the default native-voice worker, use the exact mandatory voice/transport JSON
fields in [`internal/backend/discord/voicejobs/config.go`](internal/backend/discord/voicejobs/config.go)
and the SDK transport config; those duration fields use numeric nanoseconds, not
the runtime's duration-string encoding. Voice control and packet limits must
match the runtime/transport bounds. No media tool or native dependency belongs in
the ordinary module image.

### Generate an installation

Generate configuration from an already prepared immutable image record, never
by registering a runtime epoch or fetching during launch:

```sh
sudo /usr/local/bin/chatanium prepare-image \
  --installation-id "${INSTALLATION_ID:?}" --operator --module-id "${MODULE_ID:?}" \
  --image "${MODULE_REPODIGEST:?use exact approved repository@sha256 digest}" \
  --limits-file "${PREPARE_LIMITS:?set protected complete preparation-limits JSON}"
# Review and type the exact preparation PlanDigest when prompted.
# CONFIG_CANDIDATE must be new, in an existing protected root-owned directory.
sudo /bin/sh -c 'umask 077; set -C; output=$1; shift; exec /usr/local/bin/chatanium generate-config "$@" > "$output"' \
  sh "${CONFIG_CANDIDATE:?set new protected absolute candidate path}" \
  --installation-id "$INSTALLATION_ID" \
  --module-config "${MODULE_CONFIG:?}" --approval "${MODULE_APPROVAL:?}" \
  --image "$MODULE_REPODIGEST" --module-id "$MODULE_ID" \
  --uid "${MODULE_UID:?}" --gid "${MODULE_GID:?}"
sudo /usr/local/bin/chatanium configure --installation-id "$INSTALLATION_ID" \
  --config "$CONFIG_CANDIDATE"
# Review and type the exact configuration PlanDigest and each ReviewDigest.
sudo --preserve-env=FLEXMODULE_DISCORD_BOT_TOKEN -- /usr/local/bin/chatanium start \
  --foreground --installation-id "$INSTALLATION_ID"
```

For offline preparation, supply `--source-kind oci-archive|docker-archive`,
`--input PATH` and `--archive-digest sha256:...`; root derives the offline selector
from inspected metadata. Original archive identity remains distinct from
registry provenance. Registry credentials require an explicit protected mode-0600
`--credential-file`; no ambient Docker credential discovery occurs.

The example selects explicit limits through optional `--limits-file PATH`;
omit that flag to use the root-proposed finite limits. A supplied file must be a
complete strict [`provision.PrepareLimits`](internal/provision/contracts.go) JSON
object with every positive bound: `nano_cpus`, `memory_bytes`, `tasks`,
`input_bytes`, `expanded_bytes`, `output_bytes`, `inodes`, `json_bytes`,
`descriptor_count`, `index_depth`, and `deadline`. Deadline is an integer number
of nanoseconds, not a duration string. Missing fields are not filled with defaults.
The protected file is read and validated before producing the root plan, which
displays the exact selected limits for digest approval. `--limits-file` cannot
be combined with advanced `--plan`. A known `--job-id` replay must use exactly
its recorded limits; fresh/live preparation cannot exceed its root-approved
finite ceiling or expand the original scope.
Automatically derived preparation defaults leave four retained-image slots in
the total source/cache pools: source accounting charges `2 * input_bytes`, so
default input is capped at one eighth of total source bytes; default retained
cache output and source/cache inode bounds are capped at one quarter of their
total pools. Defaults also fit currently available source/cache and temporary
work peaks, with byte bounds rounded down to 4096-byte blocks. Explicit approved
limits are validated unchanged, never silently resized to these defaults.


The generator preserves separately supplied approvals and defaults to the
inspected image argv; `--entrypoint` is an explicit absolute override.
`prepare-image --operator` is stopped root management with a displayed bounded
plan and exact digest approval. Runtime Create only uses committed prepared
records, readonly whole-cache generations and pull=never. SIGINT/SIGTERM and
optional `--duration` converge on owned drain. `make run` uses installed
self-management with INSTALLATION_ID; CONFIG is only an optional exact installed
path assertion, not a replacement or uncommitted input.

### Preparation confinement and cache publication

OCI/archive preparation, `rungv load` and development-worker inspection use a
private USER namespace owned by root, directly below the controller's host USER
namespace. Services run as Preparer with only the primary GID, no capabilities
and NoNewPrivileges. The controller verifies exact UID/GID maps, denied
setgroups, process/invocation identity and every task's authority; it independently
verifies the mount namespace and the actual approved storage binds.

The preparation gate uses domain 1, protocol 2 and filter 2. Immutable launch
metadata binds filter 2 before dispatch. After READY, native birth evidence is
recorded before ARM; FILTER_READY requires the exact installed filter digest
and all-thread TSYNC readback. Full evidence and START intent are persisted in
one transaction before START permits target data operations.

The fixed preparation-only filter rejects `sendmsg`, `sendmmsg`, `recvmsg`,
`recvmmsg` and all three io_uring syscalls, and rejects foreign syscall ABIs/x32.
Blocking ancillary ingress also prevents acquiring an outside seccomp listener
for descriptor injection. Ordinary stream/file I/O, HTTP/TLS, pure-Go DNS and
poller operations remain available. This is not the policy for `rungv run`,
module/worker IPC or CGO variants, and it is not a general ioctl allowlist.

Source/work pools remain root:root 0700. The prepared pool remains
root:RuntimeGID 0710, but each `prepared/<job>` cache envelope is root:root 0700
from birth. Only its Preparer-owned `generation` child is writable and bound as
`/chatanium/cache`; the envelope and pools are never writable target binds.
There is no pending-directory rename or durable-path change. Both cache
directories remain charged to the existing project and inode limit.

After authoritative writer/private-namespace settlement, seal `generation`
read-only in place, reclaim Work and prove its actual project usage zero. Only
then journal, synchronize and expose the envelope as root:RuntimeGID 0710 and
commit publication. Current readiness/reuse also requires immutable original
acquisition proof; hashes, chmod, a later load or a proc/FD scan cannot replace
it. Opaque envelope handles may still block full reclamation. No completed
history is backfilled; unsupported filter-1 history remains cleanup-only where
its exact complete historical proof is valid, never current admission evidence.

### Legacy quarantine and staged release preparation

Only committed legacy lineages with COMPLETE outer/internal helper histories
are eligible; pending or uncertain native work is not reclassified as complete.
Unproven legacy acquisitions and their derived caches are quarantined, not
silently adopted or made usable by recovery. Quarantine preserves immutable
history, storage claims and retention-only references, while denying launch,
candidate/readiness use, rebuild-source reuse and development reuse. Full
disposal still requires native ownership/reference and actual quota-zero proof.

When installed release A cannot perform current preparation:

1. Independently authenticate and protect the candidate release B launcher.
   Run its existing `prepare-image --installation-id ID --operator` workflow,
   or `--operator --plan PATH` for an exact reviewed plan.
2. Review the preparation bundle digest, quarantine-set digest, expected active
   revision and exact old image record being replaced before approval. Use fresh
   jobs and approved source/credential/limits; retain the resulting exact receipt.
   Publishing B's helpers/cache does not change the installed bundle, active or
   pending revision, launch authority, or RECOVERY_REQUIRED state.
3. Explicitly request ordinary recovery with `stop --installation-id ID` through
   a compatible verified launcher. Only genuine cleanup/detachment can complete
   recovery; active bindings to quarantined images still prevent start.
4. Separately review B's `update --installation-id ID`. Its full candidate must
   preserve intended modules and bind exact pre-approved replacement preparation
   plans, fresh images and receipt caches for B. Missing or ambiguous matches
   fail; existing `update --plan PATH` selects exact references without guessing
   by selector, timestamp or newest result.

Only that approved Update performs backup, pending/configuration/launcher
replacement and activation. There is no installed-A Configure workaround,
temporary module-removal bypass, cache relabeling or legacy/missing-cache rebuild
fallback. Unrelated pending work, native uncertainty, resource/secret/grant
checks and cleanup barriers are not waived by quarantine.

Isolated-child checks do not establish privileged host/runtime or final native
release acceptance; those remain pending.


### Development-only hot reload

Ordinary `make run` and `chatanium start` do not expose a reload controller.
Enable the watched workflow explicitly:

```sh
DEV_MODE=1 \
DEV_RUNTIME_USER="${DEV_RUNTIME_USER:?set the approved installed non-root, non-Docker App account}" \
INSTALLATION_ID="${INSTALLATION_ID:?set approved product installation ID}" \
make run
```

`DISABLE_VOICE=1` remains the voice opt-out. The self-managed installation and
writable image registry must already be approved. Builds/pushes run unprivileged;
only the trusted installed launcher may handle approved update/preparation/start.
The watcher never executes a user-writable checkout binary as root or gives the
nonroot dev controller Docker authority. Existing narrow noninteractive sudo
authorization is required for the installed lifecycle commands and
`inspect-config --installation-id ID` and `inspect-dev-lock --installation-id ID`;
no accounts, sudoers, mounts or services
are provisioned by the watcher. Export the configured `env:NAME` host secrets in
the invoking private environment. Installed configuration remains root:root mode
0600. The watcher reads only the exact committed configuration through that
bounded root-mediated command, retaining its bytes in private memory; neither
the builder nor runtime account needs file read access. It periodically detects
committed configuration changes and rechecks before replacing a healthy runtime.
It never accepts a separate development config path or copies, chmods or chowns
the protected configuration. The worker receives configuration through private INIT.

The watcher binds installed module IDs to unique local source manifest names,
using the same module discovery as `make build`. It never auto-installs an
unconfigured module or invents approvals. Module-only changes build an overlay
from the existing immutable image, preserving its tooling/environment, push a
new tag to the same repository, resolve its real RepoDigest, explicitly prepare
that candidate through root management, and only then request nonroot dev reload.
Development rebuilds replace only the nonroot worker and native closure after
positive cleanup. They never promote a developer-built privileged launcher,
stage, preparer, engine or root helper; those require the normal verified release update.
The unprivileged packager creates a worker-only USTAR with exact member hashes,
then streams it on stdin to `prepare-dev-worker --input - --sha256 ... --size ...`.
Only the installed bounded nonroot preparer parses candidate archives/ELF.
The returned dev-only revision is selected with `start --foreground --dev-mode
--dev-revision REV`; it never changes the active release or privileged bundle.
After new readiness the watcher discards superseded owned revisions; clean final
stop discards remaining prepared revisions. Failed/uncertain operations retain
records and never blindly resubmit, fall back or roll back.
Committed images, including successful manual reloads, survive development
restarts unless the operator changes that installation's configured image.
The protected operator JSON is not rewritten. A development cleanup receipt plus
an authoritative installed `stop` report can permit replacement after a logical
module failure; a worker receipt alone, an ordinary crash or uncertain root cleanup cannot.

Compatible rebuilds reuse a verified published base within the watcher session,
rather than growing an image layer chain on every edit. An unknown/manual image
or a changed executable path establishes a new lineage.

Native build cancellation also waits for its checkout-owned Docker compiler
container to be removed. Uncertain cleanup retains
`.tools/native-container.receipt` and blocks new native builds.

For direct host-side control, add `--dev-mode --dev-socket "$DEV_SOCKET"` to
`chatanium start`. The socket must be a direct child of the exact canonical
`StorageRoot/app/native` directory, also visible at the same physical path to
host-side clients. That directory is quota-backed and owned by the installed App
UID/GID mode 0700; `ManagementDirectory` is exactly `StorageRoot/app`, never an
installation-directory alias. No extra host bind or permissive copy is created.
The socket is mode 0600 and authenticates the caller's Unix peer UID; invoke
clients as the installed App account. No TCP endpoint or root/developer-UID
exception is exposed. Socket/image-override options without `--dev-mode` are
rejected. The watcher defaults to `StorageRoot/app/native/control.sock`;
`DEV_SOCKET` may select another direct child of that same native directory.
The builder never traverses or changes permissions on this App-private storage.
The watcher holds only the explicitly journaled root:AppGID 0440
`Installation/dev-watch.lock` across restarts, outside the detachable backing.
It gets that exact path/dev/inode/owner/mode through bounded root-mediated
`inspect-dev-lock`, never by guessing from StorageRoot. Its App-account helper
opens the existing single-link empty file read-only, takes nonblocking flock and
revalidates the canonical path/inode after acquisition. It never creates or
chmods this lock. Helper/launcher cwd stays `/`, and native client connections
close before awaiting root stop/backing detachment. Full purge refuses active
coordination handles; it cannot unlink a held lock and split lock ownership.

Initialization separately displays and approves finite AppBytes/AppInodes
(baseline 10 GiB / 65536 inodes inside the default 32 GiB DATA pool), not
additional backing capacity. App/upload/log and module budgets must fit together.
Existing upload defaults remain 32 per-instance / 256 per-host records and the
8 GiB ceiling. Nothing is allocated before plan approval. Persistent app state and
its quota claim survive normal stop/uninstall; primary-data purge needs complete
writer/reference/namespace/quota cleanup proof. Update/backup includes this app data.

```sh
sudo -n -u "${DEV_RUNTIME_USER:?installed App account}" -- curl --fail-with-body --unix-socket "${DEV_SOCKET:?canonical native socket}" \
  http://localhost/v1/modules

sudo /usr/local/bin/chatanium prepare-image --installation-id "${INSTALLATION_ID:?}" \
  --module-id "${MODULE_ID:?}" --image "${MODULE_REPODIGEST:?}"

jq -n --arg module_id "${MODULE_ID:?select an installed module}" \
  --arg expected_instance_id "${INSTANCE_ID:?use the current instance from GET}" \
  --arg image "${MODULE_REPODIGEST:?use a real locally prepared same-repository digest}" \
  '{module_id:$module_id,expected_instance_id:$expected_instance_id,image:$image}' |
  sudo -n -u "$DEV_RUNTIME_USER" -- curl --fail-with-body --unix-socket "$DEV_SOCKET" \
    -H 'Content-Type: application/json' --data-binary @- \
    http://localhost/v1/modules/reload
```

Reload requests can replace **only the image digest** of an installed module.
ModuleID, UID/GID, configuration, approval, credential bindings and revisions
are preserved. The old instance drains and must complete positive cleanup
before the normal authenticated launch path allocates a fresh InstanceID and
credentials. Persistent installation storage is retained; instance credentials,
upload refs, helper transports and scratch ownership are not reused.
Stale/concurrent requests, foreign repositories, mutable tags and incomplete
cleanup fail closed. Invalid builds/pushes/preflight leave a healthy old instance
alone; failed activation after a clean stop remains a reported failed instance,
without automatic rollback or permission expansion. Development control stays
available for an explicit corrected reload, even when every module is terminal.
The current immutable digest may also be reloaded, for example to retry a
cleanly reclaimed failed activation.


</details>

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
make check-sandbox CONFIG="${RUNTIME_CONFIG:?}" INSTALLATION_ID="${INSTALLATION_ID:?}" \
  RUNTIME=/usr/local/bin/chatanium CHECK_DEADLINE=120s OBSERVE=15s
make smoke-discord CONFIG="${RUNTIME_CONFIG:?}" INSTALLATION_ID="${INSTALLATION_ID:?}" \
  RUNTIME=/usr/local/bin/chatanium CHECK_DEADLINE=180s OBSERVE=60s
make smoke-voice CONFIG="${RUNTIME_CONFIG:?}" INSTALLATION_ID="${INSTALLATION_ID:?}" \
  RUNTIME=/usr/local/bin/chatanium CHECK_DEADLINE=180s OBSERVE=60s
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

The [Chatanium organization](https://github.com/chatanium) maintains this
repository. Source covered by the root [MIT license](LICENSE) stays MIT; its
original ThirdScam copyright notice is retained. The module-system transplant
comes from [Chatanium FlexModule](https://github.com/chatanium/flexmodule).
Its MPL-2.0 license is preserved verbatim in
[`LICENSE.flexmodule`](LICENSE.flexmodule).

FlexModule-derived files in `proto/`, `shared/`,
`internal/{runtime,host,backend,app}/`, `tools/`,
`tests/integration/`, `examples/`, `modules/audio-player/`, and the copied
`Makefile` and maintained patch work retain the original MPL terms unless more
specific existing notices apply. The HashiCorp notices in
[`proto/buf.yaml`](proto/buf.yaml) and [`proto/buf.gen.yaml`](proto/buf.gen.yaml)
remain MPL-2.0. [`modules/music-bot/LICENSE`](modules/music-bot/LICENSE) is
independently MIT. Preserve original copyright, source provenance and
dependency notices, including applicable MPL source-availability obligations.

Upstream dependencies retain their own licenses. The maintained
[DiscordGo patch stack](third_party/discordgo/README.md#licensing-and-attribution)
retains upstream BSD-style terms and Bruce Marriner's notice; it is not
relicensed by the transplant. The
[libdave ABI patch](third_party/libdave/README.md#licensing-and-attribution)
preserves libdave's MIT/Discord notice and separate dependency terms. The native
build collects installed vcpkg and system-library notices as well as native
provenance. These notices, build records and all dependencies ship inside the
static launcher and its verified immutable bundle, not as a user-installed sidecar.
Keep exact source/patch/build records and meet applicable dependencies' redistribution
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
