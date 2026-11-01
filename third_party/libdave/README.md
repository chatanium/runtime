# Maintained libdave ABI patch

This directory maintains the existing native DAVE patch, not a libdave source
checkout or upstream release binary. Native builds download the pinned source
into ignored build storage and apply `patches/0001-flexmodule-abi.patch`.

## Exact origin and pin authority

- Upstream repository: <https://github.com/discord/libdave>
- Reviewed upstream base: `6396c90aedbb9a6ee117ea9ce1ce9832af6a3375`
  (the existing SDK's libdave v1.2.2/cpp source pin).
- Patch origin: `tools/native/libdave.patch` in published Chatanium DiscordGo
  SDK `v0.30.0`, commit `f2d1806d4599ff674163be703c0d62a23d4bb524`.
- Original patch SHA-256:
  `4f315a8af3f4b464b846644aeca5054010493241762f8f2ffc85695eb3016511`.
- Maintained patch SHA-256, including the explanatory provenance header:
  `80df80ce9fb3c59c019cd9364e4e09732f3d3c40def6b6f2ca10d2d6d311a4a6`.

The maintained patch adds a provenance header only: the original code hunks are
unchanged. The authoritative native source, builder, dependency, distribution,
and patch digest configuration is `tools/native/native-lock.json`. That lock is
not merely source metadata and must retain the existing ABI and target-loader
requirements. Ordered native patch files are resolved from this directory,
not from the generated DiscordGo SDK tree.

## Preserved implementation

The patch exposes the host-only C ABI extensions
`flexDaveSessionSetProposalLimits` and `flexDaveSessionActivatePendingGroup`
through `cpp/includes/dave/flex_dave_ext.h`. It retains the current bounded MLS
proposal handling, queue accounting and reset behavior, roster reset, and
explicit authorization of media export from a pending group. This is a
source-patched downstream ABI; it is not the unmodified upstream release ABI.
No new extension, cryptographic implementation, or dependency upgrade is added.

The source patch records no upstream submission or acceptance. Its header does
not claim an author, review, or PR that is not established by the source.

## Refresh workflow

1. Export the exact locked upstream source and immutable SDK patch origin into
   disposable ignored scratch. Preserve upstream licenses and notices; do not
   modify the source SDK repository or keep a full source tree in this directory.
2. Compare proposed code hunks with the maintained implementation. For a pure
   relocation or header update, retain the original patch payload byte-for-byte.
   A functional ABI change requires separate review of both native and Go users.
3. Update the maintained patch and its digest in
   `tools/native/native-lock.json` together. Keep all unrelated source, vcpkg,
   MLS, builder, repository, loader, and distribution pins intact unless their
   changes were explicitly reviewed.
4. Independently apply the patch to the exact locked source, run the native
   build and existing ABI/target-loader gates, and exercise the native DAVE and
   voice regression tests through the repository's build tooling. A digest or
   clean patch application alone is not behavioral or live-Discord evidence.

No tests or native builds are claimed by the act of maintaining this patch.

## Licensing and attribution

libdave's upstream `LICENSE` is the MIT License with the Discord copyright
notice. Retain that license, its notices, and dependency licenses in downloaded
source and native distributions as required by their existing terms. The
existing native license/archive evidence remains part of the distribution
process. This patch records source provenance, does not assert new authorship,
and does not replace or relicense upstream notices or invent separate terms for
the extracted modifications.
