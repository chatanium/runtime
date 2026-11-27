#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
mode=${1:?Expected build, module, modules or clean}
shift
: "${BUILD_OUTPUTS:?Run through make}"
safe_file .tools/build.lock
exec 9>.tools/build.lock
flock -x 9

# Validate every output before modifying any of them, including on clean.
outputs=()
for output in $BUILD_OUTPUTS; do
    [[ "$output" == bin/* ]] || fail "Build output outside bin/: $output"
    safe_file "$output"
    outputs+=("$output")
done
if [[ "$mode" == clean ]]; then
    [[ $# == 0 ]] || fail 'Clean does not accept arguments'
    safe_path bin
    if [[ -e bin ]]; then
        [[ -d bin ]] || fail 'bin must be a directory'
        # The directory-derived module filename is owned; keep all other files,
        # including native work, native libraries and OCI evidence.
        while IFS= read -r -d '' output; do
            safe_file "$output"
            outputs+=("$output")
        done < <(find bin -path bin/voice-runtime -prune -o -path 'bin/*/*/module' -print0)
    fi
    for output in "${outputs[@]}"; do rm -f -- "$output"; done
    exit 0
fi

module_mode=false
targets=()
case "$mode" in
    module|modules)
        module_mode=true
        directories=()
        if [[ "$mode" == module ]]; then
            [[ $# == 1 ]] || fail 'Expected exactly one module directory'
            directories+=("$(resolve_module_directory "$1")")
        else
            [[ $# == 0 ]] || fail 'Module discovery does not accept arguments'
            discovered=$(list_module_directories)
            if [[ -n "$discovered" ]]; then mapfile -t directories <<< "$discovered"; fi
        fi
        for directory in "${directories[@]}"; do
            module=$(module_go_directory "$directory")
            output=$(module_build_output "$directory")
            package=.
            if [[ "$module" != "$directory" ]]; then
                if [[ "$module" == . ]]; then package=./$directory; else package=./${directory#"$module"/}; fi
            fi
            safe_file "$output"
            targets+=("$module:$package:$output")
        done
        # Application modules and OCI payloads stay static regardless of the
        # runtime's native voice mode or inherited CGO settings.
        export CGO_ENABLED=0
        mode=build
        ;;
    build)
        [[ $# -gt 0 ]] || fail 'Expected build targets'
        targets=("$@")
        ;;
    *) fail "Unknown build mode: $mode" ;;
esac
(( ${#targets[@]} )) || exit 0
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
for target in "${targets[@]}"; do
    IFS=: read -r module package output extra <<< "$target"
    [[ -n "$module" && -n "$package" && -n "$output" && -z "$extra" ]] || fail "Invalid target: $target"
    [[ "$module" == . ]] || safe_path "$module"
    [[ -f "$module/go.mod" ]] || fail "Module missing: $module"
    # Only the module mode constructs directory-derived outputs, using validated
    # source directories above. Raw target tuples can publish fixed host outputs only.
    if [[ "$module_mode" != true ]]; then
        case " $BUILD_OUTPUTS " in *" $output "*) ;; *) fail "Unowned build output: $output" ;; esac
    fi
    safe_file "$output"
    printf 'Building %s (%s) -> %s [%s/%s, CGO=%s]\n' "$module" "$package" "$output" "$GOOS" "$GOARCH" "$CGO_ENABLED"
    run python3 tools/sdk.py --go "$GO_BINARY" --module-dir "$ROOT/$module"
    # Keep the replacement alias on this generation through compilation.
    safe_file .tools/deps/discordgo.lock
    exec 8<.tools/deps/discordgo.lock
    flock -s 8
    run python3 tools/sdk.py --go "$GO_BINARY" --module-dir "$ROOT/$module" --verify-only
    mkdir -p -- "$(dirname -- "$output")"
    temporary=$(mktemp "$ROOT/$output.tmp.XXXXXXXX")
    run "$GO_BINARY" -C "$ROOT/$module" build -mod=readonly -trimpath -tags= -o "$temporary" "$package"
    safe_file "$output"
    mv -fT -- "$temporary" "$output"
    temporary=
    exec 8<&-
done
