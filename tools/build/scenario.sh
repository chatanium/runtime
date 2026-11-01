#!/usr/bin/env bash
set -euo pipefail
scenario="${1:?Expected sandbox, sandbox-policy, discord or voice}"
case "$scenario" in
    sandbox|sandbox-policy|discord|voice) ;;
    *) printf '%s\n' 'Unknown validation scenario' >&2; exit 1 ;;
esac
if [[ "$scenario" == sandbox-policy ]]; then
    # Policy execution needs installed artifacts only, not checkout Go/.tools.
    fail() { printf '%s\n' "$*" >&2; exit 1; }
else
    source "$(dirname -- "${BASH_SOURCE[0]}")/../common.sh"
fi
: "${CONFIG:?Set CONFIG to an actual approved absolute operator JSON path}" \
  "${SUPERVISOR_SOCKET:?Set SUPERVISOR_SOCKET to prepared supervisor UDS}" \
  "${SUPERVISOR_UID:?Set SUPERVISOR_UID to trusted supervisor UID}" \
  "${SUPERVISOR_MAX_BYTES:?Set SUPERVISOR_MAX_BYTES to finite control bound}" \
  "${CHECK_DEADLINE:?Set CHECK_DEADLINE to finite total scenario duration}" \
  "${OBSERVE:?Set OBSERVE to finite observation duration}"
[[ "$CHECK_DEADLINE" =~ ^[1-9][0-9]*[smh]$ && "$OBSERVE" =~ ^[1-9][0-9]*[smh]$ ]] || fail 'Scenario durations require positive integer seconds/minutes/hours (for example 60s), never zero'
[[ "$CONFIG" == /* && -f "$CONFIG" ]] || fail 'CONFIG must be an existing absolute path'
[[ "$SUPERVISOR_SOCKET" == /* && -S "$SUPERVISOR_SOCKET" ]] || fail 'Supervisor UDS unavailable; no fallback launcher'
[[ "$SUPERVISOR_UID" =~ ^[0-9]+$ && "$SUPERVISOR_MAX_BYTES" =~ ^[1-9][0-9]*$ ]] || fail 'Invalid supervisor UID/control bound'
if [[ "$scenario" == sandbox-policy ]]; then
    : "${INTEGRATION:?Set INTEGRATION to the explicitly installed trusted integration binary}" \
      "${RUNTIME:?Set RUNTIME to the installed absolute ordinary runtime}" \
      "${POLICY_PLAN:?Set POLICY_PLAN to the approved absolute operator plan}" \
      "${POLICY_RUNNER:?Set POLICY_RUNNER to the installed absolute sandbox-policy.py}" \
      "${EVIDENCE:?Set EVIDENCE to the existing private root-owned evidence directory}"
    [[ "$INTEGRATION" == /* && -f "$INTEGRATION" && -x "$INTEGRATION" ]] || fail 'INTEGRATION must be an explicitly installed absolute executable'
    [[ "$(realpath -e -- "$INTEGRATION")" == "$INTEGRATION" ]] || fail 'INTEGRATION must be canonical and symlink-free'
    # Validate before executing privileged code, not only inside that code.
    current=$INTEGRATION
    while :; do
        read -r owner permissions < <(stat -c '%u %a' -- "$current")
        [[ "$owner" == 0 ]] && (( (8#$permissions & 0022) == 0 )) || fail 'INTEGRATION and all ancestors must be root-owned and not group/world-writable'
        [[ "$current" != / ]] || break
        current=$(dirname -- "$current")
    done
    [[ "$RUNTIME" == /* && -x "$RUNTIME" && "$POLICY_PLAN" == /* && -f "$POLICY_PLAN" && "$POLICY_RUNNER" == /* && -f "$POLICY_RUNNER" && "$EVIDENCE" == /* && -d "$EVIDENCE" ]] || fail 'Policy inputs must be installed absolute paths; no automatic preparation'
    # Match the runner's bounded observer reconciliation grace on cancellation.
    exec timeout --signal=TERM --kill-after=80s "$CHECK_DEADLINE" \
        "$INTEGRATION" sandbox \
        --config "$CONFIG" --runtime "$RUNTIME" --supervisor-socket "$SUPERVISOR_SOCKET" \
        --supervisor-uid "$SUPERVISOR_UID" --supervisor-max-bytes "$SUPERVISOR_MAX_BYTES" \
        --deadline "$CHECK_DEADLINE" --observe "$OBSERVE" \
        --policy-plan "$POLICY_PLAN" --policy-runner "$POLICY_RUNNER" --evidence "$EVIDENCE"
fi
use_go
runtime=${RUNTIME:-bin/chatanium}
if [[ "$scenario" == voice ]]; then
    runtime=${RUNTIME:-bin/chatanium-voice}
    [[ -f bin/voice-runtime/provenance/native-lock.json ]] || fail 'Build real voice-enabled native artifact with make build-voice first'
fi
[[ -x "$runtime" ]] || fail 'Build the requested runtime before smoke; no automatic installs or fake success'
# The go-run harness consumes the same prepared SDK as ordinary builds.
run python3 tools/sdk.py --go "$GO_BINARY"
safe_file .tools/deps/discordgo.lock
exec 8<.tools/deps/discordgo.lock
flock -s 8
run python3 tools/sdk.py --go "$GO_BINARY" --verify-only
# Never source .env, echo config or pass a secret into module container env.
# The real harness records unavailable live observations as NOT_RUN.
run timeout --signal=TERM --kill-after=15s "$CHECK_DEADLINE" \
    "$GO_BINARY" run -mod=readonly ./tests/integration "$scenario" \
    -config "$CONFIG" -runtime "$runtime" -deadline "$CHECK_DEADLINE" -observe "$OBSERVE" \
    -supervisor-socket "$SUPERVISOR_SOCKET" -supervisor-uid "$SUPERVISOR_UID" \
    -supervisor-max-bytes "$SUPERVISOR_MAX_BYTES"
