#!/usr/bin/env bash
set -euo pipefail
scenario="${1:?Expected sandbox, sandbox-policy, discord or voice}"
fail() { printf '%s\n' "$*" >&2; exit 1; }
case "$scenario" in
    sandbox|sandbox-policy|discord|voice) ;;
    *) fail 'Unknown validation scenario' ;;
esac
# Acceptance uses installed artifacts, never go run or an alternate worker.
: "${CONFIG:?Set CONFIG to the approved installed absolute operator JSON}" \
  "${RUNTIME:?Set RUNTIME to the installed absolute static launcher}" \
  "${INTEGRATION:?Set INTEGRATION to the installed absolute integration executable}" \
  "${CHECK_DEADLINE:?Set CHECK_DEADLINE to finite total scenario duration}" \
  "${OBSERVE:?Set OBSERVE to finite observation duration}"
[[ "$CHECK_DEADLINE" =~ ^[1-9][0-9]*[smh]$ && "$OBSERVE" =~ ^[1-9][0-9]*[smh]$ ]] || fail 'Durations require positive integer seconds/minutes/hours'
trusted_path() {
    local current=$1
    [[ "$current" == /* && -f "$current" && "$(realpath -e -- "$current")" == "$current" ]] || fail 'Inputs must be canonical installed absolute files'
    while :; do
        read -r owner permissions < <(stat -c '%u %a' -- "$current")
        [[ "$owner" == 0 ]] && (( (8#$permissions & 0022) == 0 )) || fail 'Installed inputs and ancestors must be root-owned and not group/world-writable'
        [[ "$current" != / ]] || break
        current=$(dirname -- "$current")
    done
}
trusted_path "$RUNTIME"
trusted_path "$INTEGRATION"
trusted_path "$CONFIG"
[[ -x "$RUNTIME" && -x "$INTEGRATION" ]] || fail 'Installed launcher and integration executable required'
args=(--config "$CONFIG" --runtime "$RUNTIME" --deadline "$CHECK_DEADLINE" --observe "$OBSERVE")
case "${PREPARE_IMAGES:-0}" in
    0) ;;
    1) args+=(--prepare-images) ;;
    *) fail 'PREPARE_IMAGES must be 0 or 1; preparation is explicit and approval-bound' ;;
esac
if [[ "$scenario" == sandbox-policy ]]; then
    : "${POLICY_PLAN:?Set POLICY_PLAN to the approved installed case plan}" \
      "${POLICY_RUNNER:?Set POLICY_RUNNER to installed sandbox-policy.py}" \
      "${EVIDENCE:?Set EVIDENCE to the existing private root-owned evidence directory}"
    [[ "${PREPARE_IMAGES:-0}" == 0 ]] || fail 'Policy fixtures must be independently initialized and prepared before observation'
    trusted_path "$POLICY_PLAN"
    trusted_path "$POLICY_RUNNER"
    [[ "$EVIDENCE" == /* && -d "$EVIDENCE" ]] || fail 'Existing absolute evidence directory required'
    args+=(--policy-plan "$POLICY_PLAN" --policy-runner "$POLICY_RUNNER" --evidence "$EVIDENCE")
    scenario=sandbox
    grace=80s
else
    grace=15s
fi
# No checkout toolchain, ambient helper lookup, supervisor flags or runtime daemon.
exec timeout --signal=TERM --kill-after="$grace" "$CHECK_DEADLINE" "$INTEGRATION" "$scenario" "${args[@]}"
