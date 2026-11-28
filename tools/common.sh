#!/usr/bin/env bash
# Shared only by this repository's build and generation commands.
set -euo pipefail
ROOT=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd -P)
cd -- "$ROOT"

fail() { printf '%s\n' "$*" >&2; exit 1; }

# Refuse symlink traversal, directories as files, and paths outside the root.
# Check every existing component before creating or replacing an owned file.
safe_path() {
    local path=$1 part current=$ROOT
    case "$path" in ''|/*|*/|*//*|.|..|../*|*/../*|*/..|*/.|./*|*/./*) fail "Unsafe owned path: $path" ;; esac
    local -a parts
    IFS=/ read -r -a parts <<< "$path"
    for part in "${parts[@]}"; do
        current=$current/$part
        [[ ! -L "$current" ]] || fail "Symlink in owned path: $path"
    done
}

safe_file() {
    safe_path "$1"
    [[ ! -e "$1" || -f "$1" ]] || fail "Owned output is not a regular file: $1"
}

# A bare module name belongs to modules/; explicit paths stay repo-relative.
# The canonical manifest is also the discovery marker for v2 modules.
resolve_module_directory() {
    local directory=${1:?Expected module directory}
    [[ "$directory" != *[[:space:]:]* ]] || fail "Invalid module directory: $directory"
    [[ "$directory" == */* ]] || directory=modules/$directory
    safe_path "$directory"
    [[ -d "$directory" ]] || fail "Module directory missing: $directory"
    safe_file "$directory/manifest.json"
    [[ -f "$directory/manifest.json" ]] || fail "Module manifest missing: $directory/manifest.json"
    printf '%s\n' "$directory"
}

module_build_output() {
    local directory
    directory=$(resolve_module_directory "$1") || return
    printf 'bin/%s/module\n' "$directory"
}

module_go_directory() {
    local directory
    directory=$(resolve_module_directory "$1") || return
    while [[ "$directory" != . ]]; do
        safe_file "$directory/go.mod"
        if [[ -f "$directory/go.mod" ]]; then
            printf '%s\n' "$directory"
            return
        fi
        if [[ "$directory" == */* ]]; then directory=${directory%/*}; else directory=.; fi
    done
    safe_file go.mod
    [[ -f go.mod ]] || fail 'Repository go.mod missing'
    printf '.\n'
}

uses_prepared_sdk() {
    run "$GO_BINARY" -C "$ROOT/$1" mod edit -json | python3 -c '
import json, os, sys
owned = os.path.join(sys.argv[1], ".tools/deps/discordgo")
print("yes" if any(
    item["Old"]["Path"] == "github.com/bwmarrin/discordgo"
    and os.path.abspath(os.path.join(sys.argv[2], item["New"]["Path"])) == owned
    for item in json.load(sys.stdin).get("Replace") or ()
) else "no")
' "$ROOT" "$ROOT/$1"
}

list_module_directories() {
    local directory resolved
    safe_path modules
    # Only bundled modules are discovered by default. Other directories must
    # be selected explicitly, even if they have a valid manifest.
    for directory in modules/audio-player modules/music-bot; do
        [[ -d "$directory" && ! -L "$directory" && -f "$directory/manifest.json" ]] || continue
        resolved=$(resolve_module_directory "$directory") || return
        printf '%s\n' "$resolved"
    done
}

safe_path .tools
[[ ! -e .tools || -d .tools ]] || fail '.tools must be a directory'
mkdir -p -- .tools

child=
stop_child() {
    if [[ -n "$child" ]]; then
        kill -TERM -- "-$child" 2>/dev/null || true
        # Bound cancellation even if a compiler or its descendants ignore TERM.
        kill -KILL -- "-$child" 2>/dev/null || true
        wait "$child" 2>/dev/null || true
        child=
    fi
}
trap 'stop_child; exit 130' INT
trap 'stop_child; exit 143' TERM
trap 'stop_child; exit 129' HUP

# Isolate each compiler/generator process tree so cancellation reaches children.
run() {
    local status=0
    setsid --wait "$@" &
    child=$!
    wait "$child" || status=$?
    child=
    return "$status"
}

go_probe=
trap 'status=$?; stop_child; if [[ -n "$go_probe" ]]; then rm -f -- "$go_probe"; fi; exit "$status"' EXIT

use_go() {
    : "${GO_TOOLCHAIN:?Run this command through make (missing GO_TOOLCHAIN)}"
    # An inherited GOROOT may belong to a different compiler distribution.
    unset GOROOT
    export GOTOOLCHAIN=$GO_TOOLCHAIN GOWORK=off GOFLAGS=
    local actual
    GO_BINARY=$(python3 -I tools/sdk.py --find-go "$GO_TOOLCHAIN") || exit 1
    go_probe=$(mktemp .tools/go-version.XXXXXXXX)
    run "$GO_BINARY" env GOVERSION > "$go_probe"
    IFS= read -r actual < "$go_probe"
    rm -f -- "$go_probe"
    go_probe=
    [[ "$actual" == "$GO_TOOLCHAIN" ]] || fail "Go version is $actual; require $GO_TOOLCHAIN"
}

check_tools() {
    local actual directory=${1:-.tools/bin}
    safe_file "$directory/buf"
    safe_file "$directory/protoc-gen-go"
    safe_file "$directory/protoc-gen-go-grpc"
    [[ -x "$directory/buf" && -x "$directory/protoc-gen-go" && -x "$directory/protoc-gen-go-grpc" ]] || fail 'Pinned tools missing; run make tools'
    actual=$("$directory/buf" --version)
    [[ "$actual" == "$BUF_VERSION" ]] || fail "Buf is $actual; require $BUF_VERSION (run make tools)"
    actual=$("$directory/protoc-gen-go" --version)
    [[ "$actual" == "protoc-gen-go $PROTOC_GEN_GO_VERSION" ]] || fail "Go generator is $actual; require $PROTOC_GEN_GO_VERSION"
    actual=$("$directory/protoc-gen-go-grpc" --version)
    [[ "$actual" == "protoc-gen-go-grpc ${PROTOC_GEN_GO_GRPC_VERSION#v}" ]] || fail "gRPC generator is $actual; require $PROTOC_GEN_GO_GRPC_VERSION"
}
