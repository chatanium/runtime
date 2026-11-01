#!/usr/bin/env bash
set -euo pipefail
source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
use_go
check_tools
: "${CHECK_DEADLINE:=1800s}" "${TEST_TIMEOUT:=120s}"
export CHECK_DEADLINE TEST_TIMEOUT
[[ "$CHECK_DEADLINE" =~ ^[1-9][0-9]*[smh]$ && "$TEST_TIMEOUT" =~ ^[1-9][0-9]*[smh]$ ]] || fail 'Check deadlines require positive integer seconds/minutes/hours (for example 120s), never zero'
# Offline checks must not accidentally use credentials from the host shell.
unset DG_OAUTH2_TOKEN DGB_TOKEN DGU_TOKEN DG_GUILD DG_CHANNEL DG_VOICE_CHANNEL DG_ADMIN DISCORD_TOKEN
# Check maintained SDK behavior without native libraries or upstream standalone
# example modules. Root ./... includes our general example and sandbox fixture.
# Whole-suite and per-package deadlines are independent and failures propagate.
run timeout --signal=TERM --kill-after=10s "$CHECK_DEADLINE" bash -euo pipefail -c '
    python3 -I -m unittest discover -s tools -p test_sdk.py
    python3 tools/sdk.py --go "$1"
    .tools/bin/buf build proto
    bash tools/generate.sh check
    exec 8<.tools/deps/discordgo.lock
    flock -s 8
    python3 tools/sdk.py --go "$1" --verify-only
    printf "Checking offline patched SDK\n"
    CGO_ENABLED=0 "$1" -C .tools/deps/discordgo test -mod=readonly -tags= -count=1 -timeout "$TEST_TIMEOUT" .
    for module in . modules/music-bot modules/audio-player; do
        printf "Checking offline module %s\n" "$module"
        python3 tools/sdk.py --go "$1" --module-dir "$module" --verify-only
        "$1" -C "$module" test -mod=readonly -tags= -count=1 -timeout "$TEST_TIMEOUT" ./...
    done
' bash "$GO_BINARY"
