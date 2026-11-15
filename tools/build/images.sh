#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
mode=${1:?Expected module, media or build-media-modules}
[[ $# == 1 ]] || fail 'Expected one image build mode'

if [[ "$mode" == build-media-modules ]]; then
    run env CGO_ENABLED=0 bash tools/build.sh module modules/music-bot
    run env CGO_ENABLED=0 bash tools/build.sh module modules/audio-player
    exit 0
fi
[[ "$mode" == module || "$mode" == media ]] || fail 'Expected module, media or build-media-modules'
[[ "${GOOS:-linux}/${GOARCH:-amd64}" == linux/amd64 && "${CGO_ENABLED:-0}" == 0 ]] || fail 'Module images require static Linux AMD64 Go executables (CGO_ENABLED=0)'

module_inputs() {
    local prefix=$1 directory binary go_directory
    directory=$(resolve_module_directory "$2")
    binary=$(module_build_output "$directory")
    go_directory=$(module_go_directory "$directory")
    safe_file "$directory/manifest.json"
    safe_file "$binary"
    safe_file ".tools/images/$directory/image.json"
    safe_file ".tools/images/$directory/image.json.partial"
    export "${prefix}_DIRECTORY=$directory" "${prefix}_BINARY=$binary" "${prefix}_GO_DIRECTORY=$go_directory"
}

safe_path .tools/images
safe_file .tools/images/build.lock
if [[ "$mode" == module ]]; then
    module_inputs MODULE "${MODULE:-examples/general-bot}"
else
    safe_path .tools/media
    module_inputs MUSIC modules/music-bot
    module_inputs PLAYER modules/audio-player
fi
use_go
export GO_BINARY
run python3 tools/build/images.py "$mode"
