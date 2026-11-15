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
# A Docker CLI process is not the owner of daemon-side work. Persist ownership
# before create, and do not start until its exact ID is durably receipted.
receipt=$ROOT/.tools/native-container.receipt
receipt_tmp=
cid_file=
cleanup_failed=0
checkout=$(printf '%s' "$ROOT" | sha256sum)
checkout=${checkout%% *}
docker_bounded() { timeout --signal=KILL 5s docker "$@"; }
write_receipt() {
    receipt_tmp=$(mktemp "$ROOT/.tools/native-receipt.XXXXXXXX") || return 1
    printf '%s %s %s %s\n' "$daemon_id" "$checkout" "$owner" "$container_id" > "$receipt_tmp" || return 1
    mv -fT -- "$receipt_tmp" "$receipt" || return 1
    receipt_tmp=
}
remove_owned_container() {
    local record saved_daemon saved_checkout owner container_id extra actual ids identity remaining
    [[ -e "$receipt" || -L "$receipt" ]] || return 0
    [[ -f "$receipt" && ! -L "$receipt" ]] || return 1
    [[ $(stat -c '%u:%a:%h' -- "$receipt") == "$(id -u):600:1" ]] || return 1
    record=$(< "$receipt")
    read -r saved_daemon saved_checkout owner container_id extra <<< "$record" || return 1
    [[ -z "$extra" && "$record" == "$saved_daemon $saved_checkout $owner $container_id" ]] || return 1
    [[ "$saved_daemon" =~ ^[a-zA-Z0-9:-]+$ && "$saved_checkout" == "$checkout" ]] || return 1
    [[ "$owner" =~ ^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$ ]] || return 1
    [[ "$container_id" == - || "$container_id" =~ ^[0-9a-f]{64}$ ]] || return 1
    actual=$(docker_bounded info --format '{{.ID}}') || return 1
    [[ "$actual" == "$saved_daemon" ]] || return 1
    if [[ "$container_id" == - ]]; then
        ids=$(docker_bounded container ls --all --no-trunc --filter "name=^/chatanium-native-$owner$" --format '{{.ID}}') || return 1
        # A cancelled create with no known ID may still be in flight. Absence
        # cannot positively settle it; retain the receipt and never start it.
        [[ -n "$ids" ]] || return 1
    else
        ids=$(docker_bounded container ls --all --no-trunc --filter "id=$container_id" --format '{{.ID}}') || return 1
        if [[ -z "$ids" ]]; then
            rm -f -- "$receipt"
            return
        fi
        [[ "$ids" == "$container_id" ]] || return 1
    fi
    [[ "$ids" =~ ^[0-9a-f]{64}$ ]] || return 1
    identity=$(docker_bounded container inspect --format '{{.Id}} {{index .Config.Labels "io.chatanium.native.owner"}} {{index .Config.Labels "io.chatanium.native.checkout"}} {{.Name}}' "$ids") || return 1
    [[ "$identity" == "$ids $owner $checkout /chatanium-native-$owner" ]] || return 1
    docker_bounded container rm --force "$ids" >/dev/null || return 1
    remaining=$(docker_bounded container ls --all --no-trunc --filter "id=$ids" --format '{{.ID}}') || return 1
    [[ -z "$remaining" ]] || return 1
    rm -f -- "$receipt"
}
cleanup_container() {
    [[ "$cleanup_failed" == 0 ]] || return 1
    if ! remove_owned_container; then
        cleanup_failed=1
        return 1
    fi
}
cleanup() {
    local status=$?
    # Do not let a second signal interrupt the ownership barrier.
    trap '' INT TERM HUP
    stop_child
    if ! cleanup_container; then
        printf 'Native container cleanup unconfirmed; receipt retained at %s; no new native build is permitted\n' "$receipt" >&2
        status=1
    fi
    if [[ -n "$receipt_tmp" ]]; then rm -f -- "$receipt_tmp"; fi
    if [[ -n "$cid_file" ]]; then rm -f -- "$cid_file"; fi
    rm -f -- "$image_file"
    if [[ -n "$binary" ]]; then rm -f -- "$binary"; fi
    if [[ -n "$staging" ]]; then rm -rf -- "$staging"; fi
    if [[ -n "$backup" && -d "$backup" && ! -e bin/voice-runtime ]]; then mv -T -- "$backup" bin/voice-runtime; fi
    exit "$status"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
trap 'exit 129' HUP
safe_file .tools/native-container.receipt
cleanup_container || fail 'Cannot reclaim previous native build container; receipt retained'
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
daemon_id=$(docker_bounded info --format '{{.ID}}') || fail 'Cannot establish native builder Docker daemon identity'
[[ "$daemon_id" =~ ^[a-zA-Z0-9:-]+$ ]] || fail 'Docker returned an invalid daemon identity'
owner=$(< /proc/sys/kernel/random/uuid)
container_id=-
write_receipt || fail 'Cannot persist native container ownership'
cid_file=$(mktemp "$ROOT/.tools/native-cid.XXXXXXXX")
run timeout --signal=KILL 5s docker container create --init --name "chatanium-native-$owner" \
    --label "io.chatanium.native.owner=$owner" --label "io.chatanium.native.checkout=$checkout" \
    --user "$(id -u):$(id -g)" \
    --mount "type=bind,src=$ROOT,dst=/source,readonly" \
    --mount "type=bind,src=$ROOT/.tools/native,dst=/work" \
    "${go_mount[@]}" \
    -e BUILD_JOBS -e GO_TOOLCHAIN -e NATIVE_ONLY="$native_only" -e TMPDIR=/work/tmp \
    -e PYTHONDONTWRITEBYTECODE=1 \
    "$builder" python3 /source/tools/native/build.py > "$cid_file"
container_id=$(< "$cid_file")
[[ "$container_id" =~ ^[0-9a-f]{64}$ ]] || fail 'Docker returned an invalid native container ID; refusing to start'
write_receipt || fail 'Cannot persist native container ID; refusing to start'
attach_status=0
run docker container start --attach "$container_id" || attach_status=$?
result=$(docker_bounded container inspect --format '{{.State.Status}} {{.State.ExitCode}}' "$container_id") || fail 'Cannot establish native container exit status'
[[ "$result" =~ ^exited\ ([0-9]+)$ ]] || fail 'Native container did not reach an exited state'
native_status=${BASH_REMATCH[1]}
cleanup_container || fail 'Native container cleanup unconfirmed; receipt retained'
[[ "$attach_status" == 0 && "$native_status" == 0 ]] || fail 'Native compiler container failed'
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
