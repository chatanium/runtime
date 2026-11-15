#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
[[ "${GOOS:-linux}/${GOARCH:-amd64}" == linux/amd64 ]] || fail 'Native lock supports Linux AMD64 only'
mode=${1:-voice}
[[ "$mode" == voice || "$mode" == native ]] || fail 'Expected voice or native build mode'
# BoringSSL uses Go for native code generation in BOTH modes. Native-only
# excludes application Go compilation, not the pinned generator toolchain.
use_go
GO_ROOT=$("$GO_BINARY" env GOROOT)
[[ -x "$GO_ROOT/bin/go" ]] || fail 'Pinned Go compiler root missing'
go_mount=(--mount "type=bind,src=$GO_ROOT,dst=/go,readonly")
native_only=1
if [[ "$mode" == voice ]]; then native_only=0; fi
safe_path .tools/native
safe_path bin/voice-runtime
[[ ! -e bin/voice-runtime || -d bin/voice-runtime ]] || fail 'Native bundle output must be a directory'
safe_file bin/chatanium
if [[ "$mode" == voice ]]; then
    safe_file .tools/build.lock
    exec 7>.tools/build.lock
    flock -x 7
fi
safe_file .tools/native-build.lock
exec 9>.tools/native-build.lock
flock -x 9
mkdir -p .tools/native bin
# Keep all large trees and TMPDIR on the project's /home filesystem.
[[ "$ROOT" == /home/* ]] || fail 'Native workspace must be on /home; relocate the checkout, not Docker data or /tmp'
: "${BUILD_JOBS:=2}"
[[ "$BUILD_JOBS" =~ ^[1-9][0-9]*$ ]] || fail 'BUILD_JOBS must be positive'
export BUILD_JOBS
image_file=$(mktemp "$ROOT/.tools/native-builder.XXXXXXXX")
staging=
backup=
binary=
cleanup() {
    local status=$?
    stop_child
    rm -f -- "$image_file"
    if [[ -n "$binary" ]]; then rm -f -- "$binary"; fi
    if [[ -n "$staging" ]]; then rm -rf -- "$staging"; fi
    if [[ -n "$backup" && -d "$backup" && ! -e bin/voice-runtime ]]; then mv -T -- "$backup" bin/voice-runtime; fi
    exit "$status"
}
trap cleanup EXIT
# Prepare before mounting /source read-only. The local build-wide lock and
# maintained native patches stay outside the SDK and compiler image layers.
safe_file .tools/native/sdk-module.json
run python3 tools/sdk.py --go "$GO_BINARY"
# Publication needs this same lock exclusively; hold our shared lease across
# the read-only container build and all resulting provenance/output copies.
safe_file .tools/deps/discordgo.lock
exec 8<.tools/deps/discordgo.lock
flock -s 8
run python3 tools/sdk.py --go "$GO_BINARY" --verify-only --json > .tools/native/sdk-module.json
run python3 -c '
import json
from pathlib import Path

base = json.loads(Path("tools/native/native-lock.json").read_text())["builder_base"]
if f"FROM {base}" not in Path("tools/native/Builder.Dockerfile").read_text().splitlines():
    raise SystemExit("Native compiler image must match tools/native/native-lock.json builder_base")
'
run docker build --platform linux/amd64 --iidfile "$image_file" -f tools/native/Builder.Dockerfile tools/native
builder=$(< "$image_file")
[[ "$builder" =~ ^sha256:[0-9a-f]{64}$ ]] || fail 'Docker returned an invalid builder image ID'
run docker run --rm --init --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$ROOT,dst=/source,readonly" \
    --mount "type=bind,src=$ROOT/.tools/native,dst=/work" \
    "${go_mount[@]}" \
    -e BUILD_JOBS -e GO_TOOLCHAIN -e NATIVE_ONLY="$native_only" -e TMPDIR=/work/tmp \
    -e PYTHONDONTWRITEBYTECODE=1 \
    "$builder" python3 /source/tools/native/build.py
printf '%s\n' "$builder" > .tools/native/bundle/provenance/builder-image-id.txt
# Inspect actual target providers and force eager relocation before publishing.
# This verifies the current host, not an unobserved generic EL9 installation.
run env LD_LIBRARY_PATH="$ROOT/.tools/native/bundle/lib" python3 tools/native/check_abi.py \
    "$ROOT/.tools/native/bundle/lib/libdave.so" > .tools/native/bundle/provenance/target-abi.json
if [[ "$mode" == native ]]; then
    LD_LIBRARY_PATH="$ROOT/.tools/native/bundle/lib" /lib64/ld-linux-x86-64.so.2 --list .tools/native/bundle/lib/libdave.so
    printf 'Native-only outputs ready: .tools/native/prefix/{include,lib*,licenses}, .tools/native/bundle/{lib,licenses,provenance}\n'
    exit 0
fi
# Validate on the actual EL9 target loader too, before publishing any output.
LD_LIBRARY_PATH="$ROOT/.tools/native/bundle/lib" /lib64/ld-linux-x86-64.so.2 --list .tools/native/bundle/chatanium
LD_LIBRARY_PATH="$ROOT/.tools/native/bundle/lib" /lib64/ld-linux-x86-64.so.2 --list .tools/native/bundle/lib/libdave.so
staging=$(mktemp -d "$ROOT/bin/.voice-runtime.XXXXXXXX")
cp -a -- .tools/native/bundle/lib .tools/native/bundle/licenses .tools/native/bundle/provenance "$staging/"
printf '%s\n' "$builder" > "$staging/provenance/builder-image-id.txt"
binary=$(mktemp "$ROOT/bin/.chatanium.XXXXXXXX")
cp -p -- .tools/native/bundle/chatanium "$binary"
if [[ -e bin/voice-runtime ]]; then
    backup=$(mktemp -d "$ROOT/bin/.voice-runtime-backup.XXXXXXXX")
    rmdir -- "$backup"
    mv -T -- bin/voice-runtime "$backup"
fi
mv -T -- "$staging" bin/voice-runtime
staging=
safe_file bin/chatanium
mv -fT -- "$binary" bin/chatanium
binary=
if [[ -n "$backup" ]]; then rm -rf -- "$backup"; backup=; fi
printf 'Published voice-enabled bin/chatanium and bin/voice-runtime/{lib,licenses,provenance}/\n'
