# DiscordGo functional patch stack

This directory maintains patches, not a vendored SDK checkout. Preparation
downloads the exact upstream Go module and applies every `patches/NNNN-*.patch`
in lexical order into an immutable content-addressed generation at
`.tools/deps/discordgo-generations/<64hex>`. The stable relative symlink
`.tools/deps/discordgo` atomically selects the approved generation for module
replacements; resolver `Dir` values point directly to the immutable generation.
Old generations are retained rather than automatically deleted under readers.

Build scripts hold a shared `.tools/deps/discordgo.lock` lease while compilers
or native containers use the stable alias; preparation takes an exclusive
lease. Source-byte or managed-alias tampering fails validation. An unknown
directory at the owned alias is refused, not deleted. Apply the complete stack;
the Gateway and voice changes share lifecycle and handoff contracts and are not
independent replacement implementations.

## Immutable inputs and pin authority

- Upstream repository: <https://github.com/bwmarrin/discordgo>
- Upstream commit: `f43dd94faaacd5b163e9e783f14b5bd8be639fc9`
- Upstream module: `github.com/bwmarrin/discordgo`
- Version: `v0.29.1-0.20260214123928-f43dd94faaac`
- Module checksum: `h1:W9t/lhAHWwtLHME/ceUE5c49Wl+5jnOVcEezmjlJ0Fc=`
- Module-manifest checksum: `h1:JsaNXATZGUDc+uiR1/TGW4Aq4IKc2Hh/O8LhsBiSIBs=`
- Functional source: published Chatanium DiscordGo SDK `v0.30.0`, commit
  `f2d1806d4599ff674163be703c0d62a23d4bb524`, from
  <https://github.com/chatanium/discordgo>.

The root `go.mod` requirement is the version authority.
`third_party/discordgo/upstream.sum` is the sole upstream checksum authority,
containing the module and `/go.mod` entries in Go checksum format. A local
replacement causes `go mod tidy` to remove unused upstream checksums from the
root `go.sum`, so that file is not the preparation checksum authority. Consumer
requirements must match the root version, and their relative replacements must
resolve to the owned prepared tree. There is no separate SDK version lock.
This README records the reviewed base, not an alternative version-selection
mechanism. The prepared SDK retains the original upstream module directive and
self-imports. It is not a new fork release, nor an unmodified upstream release.

## Ordered logical groups

| Patch | Preserved changes |
| --- | --- |
| `0001-toolchain-and-dependencies.patch` | SDK Go 1.27.0 requirement, WebSocket v1.5.3, `x/crypto` v0.58.0 and indirect `x/sys` v0.49.0, with their existing checksums. No dependency upgrades beyond the published implementation. |
| `0002-discord-api-and-partial-state.patch` | API v10, voice endpoint correction, Stage Instance wire names and their generator mapping, nil-versus-empty message components, partial thread-member cache safety, format-safe REST logging and affected regression tests. |
| `0003-context-aware-bounded-gateway.patch` | Context-aware lifecycle and writes, bounded frame/decompression ingress, dispatch serialization and observer hooks, state synchronization, main-Gateway voice handoff, and Gateway regression tests. |
| `0004-native-dave-voice-transport.patch` | Explicit bounded voice configuration, native DAVE ownership and transitions, context-aware voice joins, authenticated UDP/Opus transport, submission/receive contracts, behavioral tests, and the root-module airhorn example's functional API migration. |

The native implementation also requires the separately maintained
[libdave ABI patch](../libdave/README.md). Ordinary non-voice builds do not link
libdave; native DAVE files and tests have `voice && cgo` build constraints.
Existing regression tests are preserved as source; their inclusion does not
claim that tests or live Discord interoperability have been exercised.

## Deliberately excluded differences

The upstream archive and licenses remain in the prepared tree. Differences in
the published fork that do not belong to the functional SDK are not replayed:

- Fork publishing identity in `go.mod`, self-imports in `voice_gateway.go`,
  `voice_transport.go` and `examples/airhorn/main.go`, and the namespace-only
  changes in `oauth2_test.go` and these example `main.go` files:
  `auto_moderation`, `autocomplete`, `avatar`, `components`, `context_menus`,
  `dm_pingpong`, `echo`, `modals`, `pingpong`, `scheduled_events`,
  `slash_commands`, `stage_instance`, and `threads`.
- Fork CI/lint configuration changes: `.github/workflows/ci.yml`,
  `.golangci.yml`, and `.travis.yml`.
- Fork publishing/documentation changes: `README.md`, `docs/GettingStarted.md`,
  `docs/index.md`, `mkdocs.yml`, `examples/README.md`,
  `examples/airhorn/README.md`, `examples/avatar/README.md`,
  `examples/voice_receive/README.md`, and `internal/dave/README.md`.
- Nested example modules `examples/linked_roles/{go.mod,go.sum,main.go}` and
  `examples/voice_receive/{go.mod,go.sum,main.go}`. These are absent from the
  upstream root-module zip. This also excludes the voice-receive demo's API
  adaptation and its Pion v3-to-v4 upgrade, not any core voice implementation or
  regression test. Their publishing identities and example checksums are not
  part of the root SDK build contract.
- Pure comment-formatting changes in `discord_test.go`, `logging.go`, and
  `oauth2.go`, and unrelated comment/blank-line reflows within `discord.go`,
  `event.go`, `state.go`, and `wsapi.go`. Formatting inseparable from changed
  implementation blocks is retained.
- SDK-owned `tools/native/libdave.patch` and `tools/native/native-lock.json`.
  Their functional inputs are maintained instead under `third_party/libdave`
  and `tools/native/native-lock.json` in this repository.

`components.go` and `interactions.go` are already identical at the two immutable
commits; no DTO additions or other upstream synchronization are included.

## Refresh workflow

1. Treat a different upstream commit or functional source tag as a new source
   review, not an automatic update. Export immutable revisions into disposable
   ignored scratch; never modify the source SDK repository or a shared Go module
   cache.
2. Compare the precise upstream root-module zip against the functional source.
   Account for all changed files, including tests, build constraints, manifests,
   and exclusions above. Retain upstream licenses and copyright notices. Use
   syntax-aware Go import rewriting when normalizing the module identity; do
   not blanket-rewrite source text.
3. Rebuild the minimal ordered functional patches, with reason, immutable
   origin, and honest upstream-disposition headers. Do not invent authors,
   reviews, or upstream submissions. Keep `go.mod` under the original upstream
   identity and preserve the implementation's required dependency versions.
4. Update the root requirement and matching consumer requirements only when the
   reviewed version changes. Maintain the two entries in `upstream.sum` from
   Go's verified isolated download of that exact upstream version, not from the
   patched tree or an unverified cache. Do not add a redundant version setting
   or checksum lock. Prepare with `python3 tools/sdk.py --json`; `--verify-only`
   validates an existing generation and alias without downloading or writing.
   Never edit the alias or any generated source to make a check pass.
5. Independently compare the prepared source inventory and Go semantics against
   the reviewed normalized functional source. Run the targeted Gateway,
   partial-state, and voice regression suites and consumer checks; native
   `voice,cgo` coverage needs the pinned patched libdave build. Refresh protocol
   provenance and generated outputs through the repository's normal tooling.
   Do not mistake a successful patch application for behavioral verification.

## Licensing and attribution

The upstream `LICENSE` contains the BSD-style terms and Bruce Marriner copyright
notice; preparation retains it unchanged. The published SDK also retains that
license. These patches extract modifications of those sources; this directory
does not replace their notices, assert new authorship, or introduce separate
license terms. Preserve the existing source notices and the required license
and attribution material when redistributing source or binaries. Native
libdave and its dependencies have their own notices, handled separately by the
native build and distribution process.
