#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
mode=${1:?Expected build, test-binary or clean}
shift
: "${BUILD_OUTPUTS:?Run through make}"
safe_file .tools/build.lock
exec 9>.tools/build.lock
flock -x 9

# Check the entire owned set before modifying any output, including on clean.
for output in $BUILD_OUTPUTS; do
    [[ "$output" == bin/* ]] || fail "Build output outside bin/: $output"
    safe_file "$output"
done
if [[ "$mode" == clean ]]; then
    for output in $BUILD_OUTPUTS; do rm -f -- "$output"; done
    exit 0
fi
[[ ( "$mode" == build || "$mode" == test-binary ) && $# -gt 0 ]] || fail 'Expected build or test-binary targets'
use_go
export GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} CGO_ENABLED=${CGO_ENABLED:-0}
if [[ "$CGO_ENABLED" == 1 ]]; then
    printf 'CGO enabled: provide CC for %s/%s and required system libraries; no native tools are installed.\n' "$GOOS" "$GOARCH"
fi

temporary=
cleanup() {
    local status=$?
    stop_child
    if [[ -n "$temporary" ]]; then rm -f -- "$temporary"; fi
    exit "$status"
}
trap cleanup EXIT
for target in "$@"; do
    IFS=: read -r module package output extra <<< "$target"
    [[ -n "$module" && -n "$package" && -n "$output" && -z "$extra" ]] || fail "Invalid target: $target"
    [[ "$module" == . ]] || safe_path "$module"
    [[ -f "$module/go.mod" ]] || fail "Module missing: $module"
    printf 'Building %s (%s) -> %s [%s/%s, CGO=%s]\n' "$module" "$package" "$output" "$GOOS" "$GOARCH" "$CGO_ENABLED"
    # Prepare and validate the owned patched SDK for every consuming module,
    # including package checks without an output binary.
    run python3 tools/sdk.py --go "$GO_BINARY" --module-dir "$ROOT/$module"
    # Keep the replacement alias on this generation through compilation.
    safe_file .tools/deps/discordgo.lock
    exec 8<.tools/deps/discordgo.lock
    flock -s 8
    run python3 tools/sdk.py --go "$GO_BINARY" --module-dir "$ROOT/$module" --verify-only
    if [[ "$output" == - ]]; then
        [[ "$mode" == build ]] || fail 'Test binaries require an owned output'
        run "$GO_BINARY" -C "$ROOT/$module" build -mod=readonly -trimpath -tags= "$package"
        exec 8<&-
        continue
    fi
    case " $BUILD_OUTPUTS " in *" $output "*) ;; *) fail "Unowned build output: $output" ;; esac
    safe_file "$output"
    mkdir -p -- "$(dirname -- "$output")"
    temporary=$(mktemp "$ROOT/$output.tmp.XXXXXXXX")
    if [[ "$mode" == test-binary ]]; then
        run "$GO_BINARY" -C "$ROOT/$module" test -c -mod=readonly -trimpath -tags= -o "$temporary" "$package"
    else
        run "$GO_BINARY" -C "$ROOT/$module" build -mod=readonly -trimpath -tags= -o "$temporary" "$package"
    fi
    safe_file "$output"
    mv -fT -- "$temporary" "$output"
    temporary=
    exec 8<&-
done
