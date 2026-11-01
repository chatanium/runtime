#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
use_go
safe_file .tools/tools.lock
exec 8>.tools/tools.lock
flock -x 8
safe_path .tools/bin
[[ ! -e .tools/bin || -d .tools/bin ]] || fail '.tools/bin must be a directory'
stage=$(mktemp -d .tools/tools.XXXXXXXX)
tools=(buf protoc-gen-go protoc-gen-go-grpc)
declare -A existed=()
touched=()
publishing=0
cleanup() {
    local status=$? tool rollback_failed=0
    stop_child
    if [[ "$publishing" == 1 ]]; then
        printf 'Tool publication failed (status %s); restoring pinned tools.\n' "$status" >&2
        for tool in "${touched[@]}"; do
            if [[ -v 'existed[$tool]' ]]; then
                if ! mv -fT -- "$stage/backup/$tool" ".tools/bin/$tool"; then
                    printf 'Tool rollback failed: %s\n' "$tool" >&2
                    rollback_failed=1
                fi
            elif ! rm -f -- ".tools/bin/$tool"; then
                printf 'Tool rollback removal failed: %s\n' "$tool" >&2
                rollback_failed=1
            fi
        done
    fi
    if [[ "$rollback_failed" == 1 ]]; then
        printf 'Tool recovery files retained at %s\n' "$stage" >&2
        exit 1
    fi
    rm -rf -- "$stage"
    exit "$status"
}
trap cleanup EXIT
# Tool executables always run on the builder, independently of target GOOS and
# GOARCH. No native voice, C/C++ compiler, ffmpeg or downloader is installed.
export GOOS=$("$GO_BINARY" env GOHOSTOS) GOARCH=$("$GO_BINARY" env GOHOSTARCH) CGO_ENABLED=0
export GOBIN=$ROOT/$stage
run "$GO_BINARY" install "github.com/bufbuild/buf/cmd/buf@v$BUF_VERSION"
run "$GO_BINARY" install "google.golang.org/protobuf/cmd/protoc-gen-go@$PROTOC_GEN_GO_VERSION"
run "$GO_BINARY" install "google.golang.org/grpc/cmd/protoc-gen-go-grpc@$PROTOC_GEN_GO_GRPC_VERSION"
check_tools "$stage"
# Generation holds a shared tools lock, so it cannot observe a mixed tool set.
mkdir -p -- .tools/bin "$stage/backup"
for tool in "${tools[@]}"; do
    safe_file ".tools/bin/$tool"
    if [[ -f ".tools/bin/$tool" ]]; then
        cp -p -- ".tools/bin/$tool" "$stage/backup/$tool"
        existed[$tool]=1
    fi
done
publishing=1
for tool in "${tools[@]}"; do
    safe_file ".tools/bin/$tool"
    touched+=("$tool")
    mv -fT -- "$stage/$tool" ".tools/bin/$tool"
done
publishing=0
printf 'Installed pinned Buf and Go generators in .tools/bin\n'
