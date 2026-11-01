#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
[[ "${GOOS:-linux}/${GOARCH:-amd64}" == linux/amd64 && "${CGO_ENABLED:-0}" == 0 ]] || fail 'Module images require static Linux AMD64 Go executables (CGO_ENABLED=0)'
use_go
export GO_BINARY
safe_path .tools/images
safe_file .tools/images/build.lock
safe_path .tools/media
for file in examples/general-bot/manifest.json modules/music-bot/manifest.json modules/audio-player/manifest.json tests/integration/fixtures/sandbox/manifest.json bin/test-module bin/chatanium-musicbot bin/voice-player-module bin/sandbox-module; do
    safe_file "$file"
done
run python3 tools/build/images.py "${1:?Expected module or media}"
