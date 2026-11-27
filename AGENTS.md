# Agent Instructions

Read [CONCEPT.md](CONCEPT.md) before designing or implementing changes. Plan before editing: identify the affected paths, compatibility boundaries and the smallest relevant verification. Update the file map below when changing repository structure. Use the proposal workflow only for proposal-driven work, not for ordinary fixes.

## Project Structure

| Path | Responsibility |
| --- | --- |
| `main.go`, `cmd/` | Launcher and user-facing CLI: `serve`, setup, review, diagnostics and maintenance. Also contains separate worker and guest helper entry points. |
| `internal/portable/` | User-local installation, verified image preparation, process supervision, IPC, sandbox policy and SQLite lifecycle ledger. |
| `internal/app/`, `internal/runtime/`, `internal/backend/` | Worker composition, backend-neutral module lifecycle and optional chat-provider adapters. |
| `internal/bundle/`, `internal/releasepayload/`, `tools/build/` | Target-specific release packaging, GVX pins, embedded payload and native release qualification. |
| `internal/bootstrap/`, Linux host service code in `internal/host/`, `tools/dev/` | Legacy Linux administration and development paths. Shared runtime contracts remain in `internal/host/`; keep the privileged paths out of portable startup. |
| `proto/`, `shared/` | Public v2 protocol and module SDK. Provider-specific Discord types are separate from `core-v2`. |
| `examples/`, `modules/`, `internal/scaffold/` | Example and bundled modules, plus scaffolding for independent modules. |
| `tests/integration/`, `tools/build/nativeacceptance/` | Integration fixtures and native release checks. |
| `docs/proposal/` | Design proposals, named by their `CHAT-N` IDs. |

## Runtime Rules

- Keep portable operation within the installation owner's user space. Do not add host accounts, services, mounts, cgroups, firewall changes or alternative engines to support default startup.
- Keep `serve` non-destructive, `doctor` read-only and reset or purge explicitly approved. Do not auto-migrate older installations or treat host storage limits as reserved space.
- Keep image identity, lifecycle and grants checked at launch. Do not give modules the host's backend credentials or substitute hard-coded guest paths for the paths supplied through the protocol.
- Use `make build-runtime` for a target-specific portable release. Do not commit generated embedded payloads. For lifecycle checks, use an isolated user data directory or disposable account rather than the operator's active installation.

## Proposal Generation

- Use unique, sequential IDs `CHAT-N`, starting at `0`. Save proposals as `docs/proposal/CHAT-N.md` using the ID alone as the filename.
- Write proposals in English, with `Seonguk Moon` as author. Mark exactly one status in bold: `Draft`, `In Review`, `Approved` or `Implemented`. Update it when the stage changes.
- For decisions that require user input, present the relevant section and wait for a response; do not use a questioning tool. Have one independent agent check the completed proposal for logical inconsistencies. Correct minor inconsistencies without changing the agreed design; obtain approval for significant changes.

## Proposal-Driven Development

1. Check the proposed scope against the codebase. Resolve contradictions in the proposal and report them before implementation. Obtain approval for significant structural changes.
2. Implement according to the approved milestones, tracking them separately. Where practical, cover consumer-visible behavior with focused tests.
3. Ask one independent `reviewer` to review the implementation. Fix actionable findings without a redundant review round.
4. Run the smallest relevant verification after integration. For UI work, keep the preview current and let the user inspect it; if they request a visual check, take one screenshot.
5. Update the proposal status after implementation and verification. Commit related changes with an English Conventional Commit; use a lowercase type and a domain scope, and avoid em dashes. Put the proposal ID in the subject text or a `Refs:` footer, never in the scope.

```text
feat(runtime): activate the worker after approved setup

Refs: CHAT-2
```
