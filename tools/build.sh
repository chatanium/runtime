#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
mode=${1:?Expected build, module, archive or clean}
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
        # Keep native work and OCI evidence outside the owned module filenames.
        while IFS= read -r -d '' output; do
            safe_file "$output"
            outputs+=("$output")
        done < <(find bin -path bin/voice-runtime -prune -o \
            \( -path 'bin/*/*/module' -o -path 'bin/*/*/module.oci.tar' \) -print0)
    fi
    for output in "${outputs[@]}"; do rm -f -- "$output"; done
    exit 0
fi

module_mode=false
archive=false
archive_color=false
archive_log() {
    local step=$1 message=$2 color=${3:-36}
    if [[ "$archive_color" == true ]]; then
        printf '\033[1;%sm[BLDR]\033[0m \033[1m[%s]\033[0m %s\n' "$color" "$step" "$message"
    else
        printf '[BLDR] [%s] %s\n' "$step" "$message"
    fi
}

targets=()
case "$mode" in
    module|archive)
        module_mode=true
        [[ $# -eq 1 ]] || fail 'Expected one module name or checkout-relative path'
        directory=$(resolve_module_directory "$1")
        if [[ "$mode" == archive ]]; then
            archive=true
            [[ "${GOOS:-linux}/${GOARCH:-amd64}" == linux/amd64 ||
                "${GOOS:-linux}/${GOARCH:-amd64}" == linux/arm64 ]] ||
                fail 'Module archives support Linux amd64 and arm64 only'
            export GOENV=off
            unset GOAMD64 GOARM64 GOEXPERIMENT GOFIPS140
            if [[ -t 1 && -n "${TERM:-}" && "$TERM" != dumb && -z "${CI:-}" && -z "${NO_COLOR:-}" ]]; then
                archive_color=true
            fi
        fi
        if [[ "$archive" == true && "$directory" == voice-runtime/* ]]; then
            fail "Module output conflicts with the native runtime: $directory"
        fi
        module=$(module_go_directory "$directory")
        output=$(module_build_output "$directory")
        package=.
        if [[ "$module" != "$directory" ]]; then
            if [[ "$module" == . ]]; then package=./$directory; else package=./${directory#"$module"/}; fi
        fi
        if [[ "$archive" == true ]]; then
            output=$output.oci.tar
            safe_file "$output"
            targets+=("$module:$package:$output:$directory")
        else
            targets+=("$module:$package:$output")
            safe_file "$output"
        fi
        # Application modules and OCI payloads stay static regardless of the
        # runtime's native voice mode or inherited CGO settings.
        export CGO_ENABLED=0
        ;;
    build)
        [[ $# -gt 0 ]] || fail 'Expected build targets'
        targets=("$@")
        ;;
    *) fail "Unknown build mode: $mode" ;;
esac
(( ${#targets[@]} )) || exit 0
if [[ "$archive" == true ]]; then archive_log 1/3 'Prepare the Go toolchain'; fi
use_go
export GOOS=${GOOS:-linux} GOARCH=${GOARCH:-amd64} CGO_ENABLED=${CGO_ENABLED:-0}
if [[ "$CGO_ENABLED" == 1 ]]; then
    printf 'CGO enabled: provide CC for %s/%s and required system libraries; no native tools are installed.\n' "$GOOS" "$GOARCH"
fi

temporary=
staging=
cleanup() {
    local status=$?
    stop_child
    if [[ -n "$temporary" ]]; then rm -f -- "$temporary"; fi
    if [[ -n "$staging" ]]; then rm -rf -- "$staging"; fi
    exit "$status"
}
trap cleanup EXIT

prepare_sdk() {
    run python3 tools/sdk.py --go "$GO_BINARY" --module-dir "$ROOT/$1"
    # Keep the replacement alias on this generation through compilation.
    safe_file .tools/deps/discordgo.lock
    exec 8<.tools/deps/discordgo.lock
    flock -s 8
    run python3 tools/sdk.py --go "$GO_BINARY" --module-dir "$ROOT/$1" --verify-only
}

for target in "${targets[@]}"; do
    IFS=: read -r module package output directory extra <<< "$target"
    [[ -n "$module" && -n "$package" && -n "$output" && -z "$extra" ]] || fail "Invalid target: $target"
    [[ "$archive" == true || -z "$directory" ]] || fail "Invalid target: $target"
    [[ "$module" == . ]] || safe_path "$module"
    [[ -f "$module/go.mod" ]] || fail "Module missing: $module"
    # Only the module mode constructs directory-derived outputs, using validated
    # source directories above. Raw target tuples can publish fixed host outputs only.
    if [[ "$module_mode" != true ]]; then
        case " $BUILD_OUTPUTS " in *" $output "*) ;; *) fail "Unowned build output: $output" ;; esac
    fi
    safe_file "$output"
    if [[ "$archive" == true ]]; then
        archive_log 2/3 "Build $directory [$GOOS/$GOARCH]"
    else
        printf 'Building %s (%s) -> %s [%s/%s, CGO=%s]\n' "$module" "$package" "$output" "$GOOS" "$GOARCH" "$CGO_ENABLED"
    fi
    needs_sdk=yes
    if [[ "$module_mode" == true && "$module" != . ]]; then
        needs_sdk=$(uses_prepared_sdk "$module")
    fi
    if [[ "$needs_sdk" == yes ]]; then
        if [[ "$archive" == true ]]; then prepare_sdk "$module" >/dev/null; else prepare_sdk "$module"; fi
    fi
    mkdir -p -- "$(dirname -- "$output")"
    if [[ "$archive" == true ]]; then
        staging=$(mktemp -d "$ROOT/$output.tmp.XXXXXXXX")
        run "$GO_BINARY" -C "$ROOT/$module" build -mod=readonly -trimpath -tags= -buildmode=exe -buildvcs=false \
            -o "$staging/module" "$package"
        archive_log 3/3 "Pack $directory"
        safe_file "$directory/manifest.json"
        run python3 tools/build/module_oci.py "$GOARCH" "$staging/module" "$directory/manifest.json" "$staging/module.oci.tar"
        safe_file "$output"
        mv -fT -- "$staging/module.oci.tar" "$output"
        rm -rf -- "$staging"
        staging=
        archive_log OK "$output" 32
    else
        temporary=$(mktemp "$ROOT/$output.tmp.XXXXXXXX")
        run "$GO_BINARY" -C "$ROOT/$module" build -mod=readonly -trimpath -tags= -o "$temporary" "$package"
        safe_file "$output"
        mv -fT -- "$temporary" "$output"
        temporary=
    fi
    if [[ "$needs_sdk" == yes ]]; then exec 8<&-; fi
done
