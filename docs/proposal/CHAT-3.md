# Portable operator control socket - Spec Proposal

| Item | Detail |
|------|--------|
| Author | Seonguk Moon |
| Created | 2026-11-28 |
| Status | **Draft** |
| Reviewers | |

---

## 1. Summary

Extend the existing owner-only control socket so a CLI or operator console can observe and manage a running portable installation without owning it. Add per-module lifecycle control, reviewed live module changes, operation tracking, logs, and measured resource usage. Keep installation-wide maintenance and runtime startup outside the socket.

## 2. Background & Motivation

The portable socket currently answers `status` with a readiness flag, stops the whole runtime, and manages live Discord ACLs. The worker already sends module state to `serve`, but a client that attaches later cannot query it. Module installation and configuration changes currently require a stopped runtime. The portable GVX launch plan disables `sandbox.stats` and `sandbox.events`; configured limits and ledger charges are not measured usage.

The operator wants to keep `chatanium serve` running separately, for example in tmux or an operator-managed `systemd --user` unit, and attach a client at any time. The independent operator console is covered by the separate CHAT-4 draft. This proposal is usable without it.

## 3. Goals & Non-Goals

### 3.1 Goals

- [ ] Discover supported operations and distinguish installation state, runtime state, and observed module state.
- [ ] Start, stop, and restart an approved module without restarting the runtime. Persist each module's automatic-start preference separately.
- [ ] Prepare images and apply one reviewed module change at a time while leaving unrelated modules running.
- [ ] Recover operation results after client disconnects without replaying mutations. Expose bounded events, logs, audit records, and metric snapshots.
- [ ] Preserve existing CLI automation, stop and ACL semantics, and native cleanup checks. Keep stopped maintenance available without a socket.

### 3.2 Non-Goals

- [ ] No TUI implementation, additional management socket, network listener, service installation, or portable daemon.
- [ ] No arbitrary signals, force kill, force unlock, guest shell or exec, pause/resume, or raw GVX RPC passthrough.
- [ ] No live data restore, forced backend reconnect, metric history, Prometheus exporter, or global runtime changes through `module.change`.
- [ ] No implicit migration, runtime restart, installation-wide reset, data deletion, or grant expansion.

## 4. Technical Design

### 4.1 Architecture Overview

`chatanium serve` remains the sole foreground owner. The same-user CLI connects to the current installation's existing epoch-bound socket. The owner validates requests, owns configuration publication and sandbox cleanup, and obtains observed module state and lifecycle results from its worker. The worker runs only approved module specs and reports observed state. Engine operations stay behind the private GVX adapter. New live clients neither open that channel nor write the live ledger. The existing `chatanium stop` path retains its durable fence before calling the owner.

The owner resolves a current snapshot for new clients even if they missed all prior events. It never infers that a module is running from the installed manifest or that cleanup succeeded from a lost socket. Preserve owner-only access, framed and bounded requests, deadlines, and epoch checks. Make `system.info` and `runtime.status` available while the socket is reachable, including startup and drain. Extend the protocol additively so old `status`, `stop`, and ACL clients retain their existing replies.

### 4.2 Data Model Changes

| Record | Required data and lifetime |
|--------|----------------------------|
| Installed module | Stable module ID, current approved image, settings, grants, resource limits, egress, and automatic-start preference. Existing modules retain automatic startup by default. Hold an exact previous approved revision and image reference when rollback is available. |
| Reviewed plan | Plan ID, installation, epoch, expiry, exact inputs and digest, and expected execution impact. A module plan binds a typed action to one module and its expected revision or absence. An image prune plan binds the exact set of images to remove. An unsubmitted plan expires on owner replacement. |
| Operation receipt | Durable operation ID, submission key, action fingerprint, target, admitted epoch and revision, progress, result, and safe error. Store it in the installation ledger before acknowledging or making side effects. Do not persist secrets or raw log bodies in receipts. |
| Observed state | Runtime phase and timestamp, per-module instance ID, state, failure, and cleanup confirmation. This state is separate from the approved configuration. |
| Observation data | Bounded event and log cursors, retained audit records, and timestamped metric samples. An audit record identifies the action, target, and outcome without retaining credentials. Metric history is not stored. |

The ledger remains authoritative for configuration, approval, admission, and cleanup. Share owner and worker state through their existing private boundary. The implementation design must specify SQLite migrations and bounds for plan expiry, receipt deduplication, logs, and audit retention. No migration of legacy installations is authorized.

### 4.3 Core Logic

**Lifecycle.** `start` uses only the current approved spec. `stop` drains one instance and confirms cleanup without uninstalling it. `restart` starts the same approved spec only after cleanup of the old instance is confirmed. `enable` and `disable` affect future `serve` starts, not the current instance. The last deliberate stop or removal leaves the owner idle. Unexpected loss is reported separately and must not be relabeled as an operator stop. An empty reviewed module set is valid for the live remove path and for subsequent startup.

**Reviewed changes.** Prepare an image before a plan that needs one. The plan covers one module and one of `install`, `remove`, `update`, `rollback`, `set_config`, `set_grants`, `set_resources`, or `set_network`. `preview` shows the exact before and after, any requested authority expansion, data retention, and whether that module must restart. Declining does not change the active configuration. `apply` takes only the reviewed plan ID. The owner verifies the current epoch, exact target revision, image and approval, available budget, and other current preconditions before claiming the plan. Shared configuration publication must not change unrelated module specs or invalidate their active runs. No caller supplies an arbitrary configuration patch.

A live install plan records two separate choices: start now and start on the next `serve`. Neither choice implies the other, and the plan must show both before approval. Removal confirms cleanup before it removes the module from the installed set. It retains persistent data. Updates and rollbacks use immutable verified images, affect only the target module, and leave data untouched. A change to a stopped module does not start it. Where a running module must restart, report approved configuration publication and observed instance state separately. A saved `v2` configuration with a failed start is not a successful launch or an implicit rollback. Changes to the runtime budget, host credentials, installed binary, or image contents are outside `module.change`. A module that requires a backend absent from the current runtime cannot provision it through this API.

**Open for proposal review:** decide whether a live reinstall can explicitly request reuse of retained data or must use the stopped data-restore path. The draft authorizes neither automatic attachment nor deletion. Until that decision is approved, a live install for an ID with retained data fails without changing it.

Current admission and module review bind to the installation-wide configuration revision and digest. Live publication must retain each existing run's exact approved inputs and bind new admission to the target module's current approval. A change to one module cannot reapprove another module, rewrite a live run's approval, or invalidate its cleanup evidence.

Publish changes to the owner's eligible Discord ACL catalog and its configuration revision with the module revision. Preserve scopes whose existing approval binding is unchanged. When the binding changes, invalidate pending reviews and run the existing ACL binding checks before activation. Do not carry live scopes into a changed image or grant binding by module ID alone.

**Operation recovery.** Admit each new job no more than once for the same submission key and payload. The reviewed plan ID is the submission key for both apply operations. Once admitted, it can retrieve the original receipt even if the approval can no longer admit a new operation. Other new submissions take a client-generated key. Reject a different payload under the same key. Closing a client does not cancel a job. Accept cancellation while the job is queued, before side effects begin. After that point return the receipt and actual progress, not `cancelled`. After owner replacement, reconcile unfinished operations against recorded evidence. Report an unconfirmed outcome or cleanup pending instead of replaying a side effect. Once an accepted key is no longer retained, it must not become valid for fresh admission. Existing synchronous `stop` and ACL operations retain their current contracts and are not automatically retried.

**Observations.** Return a current snapshot first, followed by bounded reads after a cursor. Distinguish a lost or expired cursor from an empty page. Send debug-safe and display-safe values without credentials. Separate approved limits, ledger charges, and actual usage. Every measured value has a collection time and, where relevant, a sample interval or counter scope. A missing measurement is `unavailable`, never zero.

| Metric scope | Snapshot contents |
|--------------|-------------------|
| Runtime and lifecycle | Uptime, worker phase, module counts by observed state, recent start/stop failures, instance uptime, startup duration, restart count, and last exit reason and time. |
| Guest resources | CPU utilization, memory usage, current PIDs, TX/RX bytes and rates. Show approved limits separately. Verify native data collection on each supported target before advertising it. |
| Event processing | Queue depth and bytes, incomplete events, processing throughput and latency, errors, and drops. |
| Backend | Connection state and reconnects, Discord Gateway latency, request and failure counts, and rate-limit observations. |
| Storage | Budget, accounted maxima, and measured disk use for module data, scratch, image cache, logs, and backups. |

## 5. API Design

### 5-1. New / Modified

The following are framed operation names, not HTTP routes. `mutation key` means a request ID for new mutations, except where the operation takes an approved plan ID.

| Operation | Input and result |
|-----------|------------------|
| `status`, `stop` | Unchanged and not gated on the ready phase. `status` returns only `ready`. `stop` returns success only after cleanup is confirmed. |
| `system.info` | Returns protocol and runtime versions, supported operations, and metric capabilities. |
| `runtime.status` | Returns phase, epoch, configuration revision, uptime, worker state, and whether cleanup is pending. |
| `module.list`, `module.inspect` | List installed modules or inspect a given module ID. Return approved metadata and separately timestamped observed state. |
| `module.start`, `module.stop`, `module.restart` | Module ID, expected module revision, expected instance ID when targeting an instance, and mutation key. Reject a changed target before admitting the job. Return an operation receipt. |
| `module.enable`, `module.disable` | Module ID, expected module revision, and mutation key. Return a receipt for the persisted automatic-start preference. |
| `image.prepare`, `image.list`, `image.inspect` | Prepare a bounded verified source and return an operation receipt. For a registry source, `image.prepare` first returns the bounded preparation plan without fetching; submission requires approval of the exact source digest, allowed origins, and bounds before registry I/O. Local archive inspection stays networkless. List prepared images or inspect a given image ID, including digest and state. |
| `image.prune.preview`, `image.prune.apply` | Preview exact unreferenced images and estimated reclaimed bytes. Apply only the reviewed plan ID and return an operation receipt. Recheck active and cleanup-pending runs, retained revisions, backups, and in-flight operations before deletion. |
| `module.change.preview`, `module.change.apply` | Preview a typed change for one module. Apply by plan ID and return the operation receipt. |
| `operation.list`, `operation.status`, `operation.cancel` | Page receipts, find one by operation ID or submission key, or request cancellation by operation ID. |
| `event.read`, `log.read`, `audit.read` | Accept a cursor, page bound, and applicable filters. Return matching entries and a next cursor. CLI follow uses repeated reads. |
| `metrics.snapshot`, `storage.usage` | Return measured values or explicit unavailability. Storage reports the budget, ledger charges, and measured bytes separately. |
| `backend.list`, `backend.inspect` | Return backend status and summary, or details for one backend, without returning secret values. |
| `acl.show`, `acl.guilds`, `acl.channels`, `acl.preview`, `acl.apply` | Unchanged. Discord ACL review and live application remain separate from module launch approval. |

CLI actions such as `module install <source>`, `module remove <id>`, `module update <id> <source>`, `module rollback <id>`, and `module config set`, `module grants set`, `module resources set`, and `module network set` use `module.change` when online. `module list/inspect/start/stop/restart/enable/disable` map to their corresponding operations. Existing `module install <oci-archive>` retains its stopped path. Report the chosen path; do not fall back to mutation offline when a live request has an unknown result. Existing `new`, `prepare-image`, `generate-config`, `configure`, `inspect-config`, and machine-readable output retain their contracts.

For live changes, `--plan-only` prints the plan ID, exact digest, and review. `--plan-id` with `--approve` submits that exact plan in scripted mode. For job submissions that do not use a plan ID, accept a caller-supplied `--request-id` and make any generated key available before transmission. `operation list`, `operation status <operation-id-or-submission-key>`, and `operation cancel <operation-id>` expose receipt recovery and cancellation. An ID identifies a plan or submission; a plan ID does not replace the CLI digest comparison.

| Local CLI only | Contract |
|----------------|----------|
| `serve`, `doctor`, `init` (`reset`), `update`, `uninstall`, `purge`, `bind-restored-volumes` | Keep existing behavior. Startup and runtime restart belong to the operator or external supervisor. `doctor` stays read-only. |
| `runtime recover` | Retry pending cleanup without starting the runtime. Require exclusive maintenance ownership. Keep the fence if a previous owner's or sandbox's exit or cleanup cannot be confirmed. |
| `backup list/create/verify/restore` | Create and restore require a stopped installation. Creation seals the member inventory and returns the backup ID and inventory digest for independent retention. Exclude host credentials. Restore requires explicit review, an independently retained inventory digest, a fresh private destination at the approved path, and existing sealed-member verification and volume binding. Never overlay a live installation. |
| `module data export/restore/purge` | Require exclusive access to a stopped installation and confirmed target cleanup. Export a consistent stopped source. Review and approve restore and purge separately. Removing or rolling back a module does not perform any of these operations. |
| `backend credentials rotate <backend>` | Replace owner-held credentials while stopped. Read from a hidden prompt or owner-only file, never command arguments or the control socket. |
| `diagnostics export` | Collect operator-safe diagnostics even without a running owner. Do not include secrets. |

### 5-2. Error Handling

| Condition | Required behavior |
|-----------|-------------------|
| Bad frame, unsupported operation, wrong epoch, or operation unavailable in this owner phase | Reject without executing. Rediscover the current owner if the epoch changed. Do not replay mutations automatically. |
| Unknown module/image/backend, invalid plan, or changed revision | Return the affected target and safe next action. A stale or expired unsubmitted plan requires a new review. |
| Repeated key, running operation, or non-cancellable phase | Return the original receipt for the same submission, reject a conflicting submission, or report why cancellation is no longer available. |
| Unconfirmed native exit or cleanup | Return `CLEANUP_PENDING` and prevent replacement or reclamation until there is proof. |
| Failure after a configuration commit | Report the committed revision separately from observed runtime failure. Do not present it as an unapplied plan. |
| Stale cursor or unavailable metric | Report the missing range or measurement explicitly. Do not fabricate historical data or a zero. |

## 6. Implementation Plan

### 6-1. Milestones

Each phase has a separately verifiable operator outcome. Owner and duration have not been assigned.

| Phase | Task | Estimated Duration | Owner |
|-------|------|--------------------|-------|
| 1 | Add capability discovery and read-only runtime, module, and backend snapshots. Verify late attach and reconnect without mutating an installation. | Not assigned | Not assigned |
| 2 | Add operation receipts and per-module lifecycle control. Verify duplicate submission, last-module stop, and cleanup failure. | Not assigned | Not assigned |
| 3 | Add image operations and reviewed live module changes. Verify concurrent review invalidation, empty configuration, and outcomes after publication or cleanup failures. | Not assigned | Not assigned |
| 4 | Add bounded events, logs, audit reads, storage observations, and metrics. Verify actual sampling and unavailable reporting on native targets. | Not assigned | Not assigned |
| 5 | Add the stopped maintenance CLI. Verify recovery, backup and module-data boundaries, and secret-free diagnostics in an isolated installation. | Not assigned | Not assigned |

### 6-2. Dependencies

Existing owner IPC, worker message framing, SQLite ledger, reviewed portable image preparation, and the pinned GVX adapter. Native sampling support must be verified for Linux amd64/arm64, macOS arm64, and Windows amd64/arm64. The socket extension does not depend on the TUI or on a new service.

## 7. References

- [Product concept](../../CONCEPT.md), [portable v2 design](CHAT-1.md), and [operator workflow inventory](CHAT-2.md).
- [Owner control socket](../../internal/portable/service/control.go), [foreground service](../../internal/portable/service/service.go), and [worker protocol](../../internal/portable/session/wire.go).
- [Portable worker](../../internal/portable/worker/worker.go), [module CLI](../../internal/cli/module.go), [stopped configuration review](../../internal/portable/install/configure.go), and [local module installation](../../internal/portable/install/module_install.go).
- [Discord ACL](../../internal/portable/service/discord_acl.go), [GVX launch plan](../../internal/portable/engine/plan.go), and [storage accounting](../../internal/portable/store/budget.go).
