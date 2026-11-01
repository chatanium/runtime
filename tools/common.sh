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
    case "$path" in ''|/*|*/|*//*|.|..|../*|*/../*|*/..|./*|*/./*) fail "Unsafe owned path: $path" ;; esac
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
    # Version-manager shims may reject .go-version before Go can handle
    # GOTOOLCHAIN. Select an actual bootstrap binary, never such a shim.
    GO_BINARY=${BOOTSTRAP_GO:-}
    if [[ -z "$GO_BINARY" && -x .tools/go/bin/go ]]; then
        safe_file .tools/go/bin/go
        GO_BINARY=$ROOT/.tools/go/bin/go
    fi
    if [[ -z "$GO_BINARY" ]]; then
        local candidate
        while IFS= read -r candidate; do
            [[ "$candidate" != */shims/* ]] || continue
            GO_BINARY=$candidate
            break
        done < <(type -a -p go || true)
    fi
    [[ "$GO_BINARY" == /* && -x "$GO_BINARY" ]] || fail 'Set BOOTSTRAP_GO to an actual Go binary, or install the pinned Go distribution in .tools/go'
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
