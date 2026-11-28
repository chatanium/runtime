#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
[[ $# == 0 ]] || fail 'Image build does not accept positional arguments'

target="${GOOS:-linux}/${GOARCH:-amd64}"
[[ "$target" == linux/amd64 || "$target" == linux/arm64 ]] ||
    fail 'Module images support Linux amd64/arm64 only'
[[ "${CGO_ENABLED:-0}" == 0 ]] || fail 'Module images require static Go executables (CGO_ENABLED=0)'

MODULE_DIRECTORY=$(resolve_module_directory "${MODULE:-examples/general-bot}")
MODULE_BINARY=$(module_build_output "$MODULE_DIRECTORY")
MODULE_GO_DIRECTORY=$(module_go_directory "$MODULE_DIRECTORY")
safe_file "$MODULE_BINARY"
safe_file ".tools/images/$MODULE_DIRECTORY/image.json"
safe_file ".tools/images/$MODULE_DIRECTORY/image.json.partial"
export MODULE_DIRECTORY MODULE_BINARY MODULE_GO_DIRECTORY
safe_path .tools/images
safe_file .tools/images/build.lock
use_go
export GO_BINARY
run python3 tools/build/images.py
