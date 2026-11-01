#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/common.sh"
mode=${1:?Expected publish or check}
[[ "$mode" == publish || "$mode" == check ]] || fail 'Expected publish or check'
: "${GENERATED_FILES:?Run through make}" "${GENERATED_EXPECTED_FILES:?Run through make}"
safe_file .tools/tools.lock
safe_file .tools/generate.lock
exec 8>.tools/tools.lock
flock -s 8
exec 9>.tools/generate.lock
flock -x 9
check_tools

read -r -a owned <<< "$GENERATED_FILES"
read -r -a expected <<< "$GENERATED_EXPECTED_FILES"
declare -A ownership=() wanted=() existed=()
for file in "${owned[@]}"; do
    [[ "$file" =~ ^[a-zA-Z0-9_/-]+\.pb\.go$ ]] || fail "Invalid generated file: $file"
    safe_file "proto/$file"
    [[ ! -v 'ownership[$file]' ]] || fail "Duplicate owned generated path: $file"
    ownership[$file]=1
done
for file in "${expected[@]}"; do
    [[ -v 'ownership[$file]' ]] || fail "Generated output has no ownership: $file"
    [[ ! -v 'wanted[$file]' ]] || fail "Duplicate expected generated path: $file"
    wanted[$file]=1
done
stage=$(mktemp -d .tools/generate.XXXXXXXX)
publishing=0
touched=()
cleanup() {
    local status=$? rollback_failed=0 file
    stop_child
    if [[ "$publishing" == 1 ]]; then
        printf 'Generation publication failed (status %s); restoring owned files.\n' "$status" >&2
        for file in "${touched[@]}"; do
            if [[ -v 'existed[$file]' ]]; then
                if ! mv -fT -- "$stage/backup/$file" "proto/$file"; then
                    printf 'Rollback failed: proto/%s\n' "$file" >&2
                    rollback_failed=1
                fi
            elif ! rm -f -- "proto/$file"; then
                printf 'Rollback removal failed: proto/%s\n' "$file" >&2
                rollback_failed=1
            fi
        done
    fi
    if [[ "$rollback_failed" == 1 ]]; then
        printf 'Recovery files retained at %s (original status %s).\n' "$stage" "$status" >&2
        exit 1
    fi
    rm -rf -- "$stage"
    exit "$status"
}
trap cleanup EXIT
mkdir -- "$stage/new" "$stage/backup"
# Buf and the template run in proto/, making both local plugin paths explicit.
# The isolated process group includes Buf and all generator subprocesses.
run bash -c 'cd -- "$1"; shift; exec "$@"' bash "$ROOT/proto" \
    "$ROOT/.tools/bin/buf" generate --template buf.gen.yaml --output "$ROOT/$stage/new"

# Validate the complete staging tree, not just the files we expect to see.
find "$stage/new" -mindepth 1 ! -type d ! -type f -print > "$stage/special"
[[ ! -s "$stage/special" ]] || fail 'Generator produced a symlink or non-regular output'
find "$stage/new" -type f -printf '%P\n' > "$stage/actual"
while IFS= read -r file; do
    [[ -v 'wanted[$file]' ]] || fail "Unexpected generated output: $file"
done < "$stage/actual"
for file in "${expected[@]}"; do
    [[ -f "$stage/new/$file" ]] || fail "Missing generated output: $file"
done

if [[ "$mode" == check ]]; then
    different=0
    for file in "${owned[@]}"; do
        if [[ -v 'wanted[$file]' ]]; then
            if ! cmp -s -- "$stage/new/$file" "proto/$file"; then
                printf 'Generated output differs: proto/%s\n' "$file" >&2
                different=1
            fi
        elif [[ -e "proto/$file" ]]; then
            printf 'Obsolete owned output remains: proto/%s\n' "$file" >&2
            different=1
        fi
    done
    exit "$different"
fi

# Back up every existing owned file before the first tree mutation. Old paths
# absent from the expected list remain owned solely for obsolete-file removal.
for file in "${owned[@]}"; do
    safe_file "proto/$file"
    if [[ -f "proto/$file" ]]; then
        mkdir -p -- "$stage/backup/$(dirname -- "$file")"
        cp -p -- "proto/$file" "$stage/backup/$file"
        existed[$file]=1
    fi
done
publishing=1
for file in "${owned[@]}"; do
    safe_file "proto/$file"
    touched+=("$file")
    if [[ -v 'wanted[$file]' ]]; then
        mkdir -p -- "proto/$(dirname -- "$file")"
        mv -fT -- "$stage/new/$file" "proto/$file"
    else
        rm -f -- "proto/$file"
    fi
done
publishing=0
printf 'Published %s owned generated files.\n' "${#expected[@]}"
