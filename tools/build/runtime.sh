#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
[[ $(uname -s) == Linux ]] || fail 'Build portable-v2 artifacts on a Linux build host (all five targets can cross-compile)'
[[ "${DISABLE_VOICE:-1}" == 1 ]] || fail 'This portable-v2 distribution does not include a verified native voice closure'
export GOENV=off
unset GOEXPERIMENT GOFIPS140
export CHATANIUM_BUILD_TTY=0
if [[ -t 1 && -n "${TERM:-}" && "$TERM" != dumb && -z "${CI:-}" ]]; then
    export CHATANIUM_BUILD_TTY=1
fi
if [[ "$CHATANIUM_BUILD_TTY" == 1 && -z "${NO_COLOR:-}" ]]; then
    printf '\033[1;36m[ RT ]\033[0m \033[1m[1/3]\033[0m Prepare the Go toolchain and SDK\n'
else
    printf '[ RT ] [1/3] Prepare the Go toolchain and SDK\n'
fi
use_go
export GO_BINARY
safe_file .tools/release-build.lock
exec 6>.tools/release-build.lock
flock -x 6
for path in .tools/release/portable internal/releasepayload/assets bin; do safe_path "$path"; done
run python3 tools/sdk.py --go "$GO_BINARY" >/dev/null
safe_file .tools/deps/discordgo.lock
exec 8<.tools/deps/discordgo.lock
flock -s 8
run python3 tools/build/release.py "${GOOS:?Missing GOOS}/${GOARCH:?Missing GOARCH}"
