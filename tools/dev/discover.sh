#!/usr/bin/env bash
# Preserve source matching for the explicitly selected legacy installation.
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
case "${1:-}" in
    sources)
        declare -A seen=()
        directories=()
        discovered=$(list_module_directories)
        if [[ -n "$discovered" ]]; then mapfile -t directories <<< "$discovered"; fi
        if [[ -n "${MODULE:-}" ]]; then directories+=("$(resolve_module_directory "$MODULE")"); fi
        for directory in "${directories[@]}"; do
            [[ -z "${seen[$directory]:-}" ]] || continue
            seen[$directory]=1
            printf '%s\t%s\t%s\n' "$directory" "$(module_go_directory "$directory")" "$(module_build_output "$directory")"
        done
        ;;
    validate)
        [[ $# == 2 ]] || fail 'Expected one canonical manifest path'
        use_go
        safe_file .tools/deps/discordgo.lock
        exec 8<.tools/deps/discordgo.lock
        flock -s 8
        run "$GO_BINARY" run -mod=readonly ./tools/build/manifest "$2" >/dev/null
        ;;
    *) fail 'Expected sources or validate' ;;
esac
