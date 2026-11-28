# Operator and developer workflow friction - Spec Proposal

| Item | Detail |
|------|--------|
| Author | Seonguk Moon |
| Created | 2026-11-28 |
| Status | **Draft** |
| Reviewers | |

---

## 1. Summary

A person with a downloaded module should be able to verify the launcher, review what the module can do, and run it without learning the build system. This inventory identifies steps to remove, automate, combine, retain, or verify across that path, the advanced operator commands, and the developer tools. It proposes choices for review, not an implementation or a change to the separately approved Discord access controls.

## 2. Background & Motivation

[CONCEPT.md][concept] draws the line at the operator's decision: combine steps when there is no choice between them, but keep approval before changing what can run, granting access, or destroying data. The source already makes some of these distinctions. For example, `module install` inspects a local archive in a guest, asks for approval, and saves a **stopped** configuration. Building the archive, identifying its publisher, installing it, and observing the module run answer four different questions.

The source audit began at `790f131820`, before the live ACL changes. This draft reflects the current checkout, including the CLI and worker package moves and the separation of independently owned module sources. It does not describe a verified release. Priorities and proposed simplifications are judgments; no timings, failure rates, or usability-study results were measured.

The owner-only control socket, live Discord ACL, and token-only starter install are separately approved and implemented (`2bf28906c5`, `5eac98a779`, `1043429394`). A new Discord starter starts with no resource access. Installation confirms capability ceilings, not live resource scope. The owner grants scope later with `acl set` and can inspect it with `acl show`. Existing modules keep their previously approved configuration until explicitly brought under a live ACL; live scope does not supersede that approval. The shipped state of a release was not audited.

## 3. Goals & Non-Goals

### 3.1 Goals

- [ ] Identify who takes each step, what they must supply, and which steps already happen automatically.
- [ ] Give each finding a disposition, a review priority, source evidence, and a boundary that any simplification must preserve.
- [ ] Give the operator a way to decide on a change from its command, review, result, and failure behavior, including the scripted path.

### 3.2 Non-Goals

- [ ] Implement any recommendation, introduce a new command or API, or prescribe an owner or delivery date.
- [ ] Redesign live ACL rules, the control transport, Discord identity discovery, or the approved install review. Do not apply the old install-time resource picker to the new flow.
- [ ] Qualify a release, run a live bot, migrate a legacy installation, enable host features, or weaken a trust, resource, or cleanup check.

## 4. Technical Design

### 4.1 Architecture Overview

No runtime architecture change is proposed. Use the boundaries between these paths when evaluating a handoff:

| Path | What the result establishes | What it does not establish |
|------|------|------|
| Release publisher → operator | Independently verified provenance ties the selected launcher to its publisher and release. Native acceptance evidence is target-specific. | A checksum beside a download does not authenticate it. A Linux cross-build is not a native run of the target. |
| Source → executable → OCI archive or tagged image | The build produced an artifact for a particular guest architecture and declaration. | It is not installed. An image label requests capabilities; it cannot approve them. |
| Local archive or pinned registry → prepared image → reviewed configuration | Preparation identifies the image. The owner reviews the settings, capabilities, limits, and egress before publishing the stopped configuration. | A prepared image or generated candidate cannot launch itself. An archive hash is not a publisher identity. |
| Foreground owner → worker → module guest | `serve` starts the reviewed configuration. Worker events report the state of the worker and individual modules. | `READY` does not prove message delivery, an allowed Discord operation, or audible voice. The bot token belongs to the host. |
| Owner → stopped maintenance | A verified update, sealed backup, or exact deletion plan can authorize its particular operation. | A filesystem copy, missing socket, or old approval is not authority to restore, reclaim, or delete new data. |

### 4.2 Data Model Changes

No changes. The only artifact is this document. It introduces no manifest field, grant, ACL record, configuration format, ledger entry, or telemetry collection.

### 4.3 Core Logic

Classify the *human step*, not the underlying check. **Remove** a step that adds no decision; **automate** mechanical work on known inputs; **combine** steps when every authority decision remains reviewable and bound to the exact plan; **retain** a useful decision or safeguard; **verify** a discrepancy or unresolved need before choosing a remedy. P1 means a first-use blocker, a trust or data-loss risk, or a misleading claim of success. P2 means repeated work or a hard-to-find recovery path. P3 includes minor wording, discoverability, and keystroke costs. These are review priorities, not a delivery order. All directions below are draft candidates unless marked as a separate approved baseline.

#### Obtain the runtime, start it, and understand the output

| ID / evidence | Current step or burden | Disposition | Candidate and security retention |
|------|------|------|------|
| R1 [Release workflow][release], [guide][portable] | Select the OS/architecture asset and verify the outer launcher before executing it. The detailed attestation example is under the legacy Linux runbook. | Combine · P1 | Put asset selection and independent verification together for portable v2. Check the expected publisher, workflow, tag, commit, target, and artifact. Neither `SHA256SUMS` from the same download nor the embedded GVX pin replaces publisher authentication. |
| R2 [Prerequisites][portable], [runtime builder][runtime-build] | Linux amd64/arm64 uses `systrap`, macOS arm64 `hvf`, and Windows amd64/arm64 `whpx`. WHPX must already be enabled. Source-build instructions appear before the portable guide. | Remove · P1 | Remove build-tool, Docker, and native-voice detours from the download-and-run path. Give a target-specific prerequisite or an unsupported result; never enable a hypervisor, install host packages, create accounts, or substitute an engine. |
| R3 [Installation paths][paths], [guide][portable] | The launcher selects one installation under the account's data directory. Another account, data home, or an older named installation can lead the operator to look in the wrong place. | Retain · P2 | Show the resolved path and owning-account requirement. Do not ask for an installation ID on the portable path, silently migrate an old tree, follow links, or adopt another owner's files. |
| R4 [Setup][setup], [initial plan][init], [review summaries][review] | Fresh `serve` proposes the location and disk budget. It can start idle after one ordinary confirmation covering the exact empty configuration. Repeat `serve` reuses `READY`; first-use options on that state produce a warning. | Retain · P1 | Lead with `serve` rather than compulsory `doctor` then `init`. Keep the review, the warning, and the distinction between a logical byte maximum and reserved host capacity. Never apply new first-use options behind that warning. |
| R5 [Setup][setup], [initial activation][activation] | Any first-module image or grant flag selects the advanced setup path. An `INITIALIZING` installation can continue; changing its approved disk budget or serving another retained state fails. | Combine · P2 | Present the remaining stage and its required inputs together. Continue only work authorized for this installation and plan. Do not restart setup as a reset, silently expand the budget, or reuse approval for a different module. |
| R6 [Doctor][init], [presentation][results] | `doctor` distinguishes matching installed files from `DIFFERENT_LAUNCHER`, `FAILED`, and inapplicable checks. It does not try write access, locking, GVX execution, or isolation. | Retain · P1 | Explain which launcher and installation were checked, the next safe action, and what was not tested. Keep it optional and read-only. A successful manifest check is not a sandbox test. |
| R7 [Root/help][root], [terminal][terminal], [events][results] | Help groups commands by task and offers shell completion. Interactive `serve` reports module state changes and the stop action; scripts get newline-delimited events. `--duration` is an optional observation interval. | Combine · P3 | Put the short paths and their expected end states in help. Keep module diagnostics on stderr, structured events on stdout, safe display of untrusted names, and usable output with `NO_COLOR`, redirection, or CI. Do not equate a timer expiring with successful module behavior. |
| R8 [CLI approval][flags], [setup approval][setup-approval], [reset][reset-cmd], [module CLI][module-cli] | `--approval` names a proposed grants file; `--approve` supplies ordered digests; `--json` selects result output; `--json-approvals` prints plans. The applicable input prompt depends on the command, not just the output format. | Combine · P1 | Put these four meanings and the exceptions in one place (section 5). Preserve exact comparisons, order, bounded input, and explicit destructive confirmation. Never echo a digest from an untrusted prompt back as consent. |
| R9 [Terminal digest prompt][flags], [preparation][prepare], [configuration][configure], [update][update], [purge][remove] | In an ordinary terminal, `prepare-image`, `configure`, `update`, and `purge` ask a person to transcribe a digest printed by the same command. The guarded operation already supplies this digest to the approval callback. | Remove · P1 | After a complete review, prompt with an action-specific `[y/N]` only when stdin, stdout, and stderr are attached to terminals. Bind the answer internally to the exact plan. Redirected input or output uses ordered expected digests, even if the other streams are terminals. A new plan needs a new review. Keep the independent restore receipt (L6). A5 addresses the number of human confirmations. |

#### Create, install, and change a module

| ID / evidence | Current step or burden | Disposition | Candidate and security retention |
|------|------|------|------|
| M1 [Scaffold command][new], [TUI][tui] | Without `--name`, choose Local check or Discord bot, enter a name, then confirm the path. Even an explicit `--template` still opens the chooser. Enter at the final `[y/N]` cancels; there is no back-to-edit key there. | Remove · P3 | Consider skipping an already supplied choice or allowing correction without starting over. Keep the destination visible, cancel without creating on decline, and retain `--name` for scripts. |
| M2 [Scaffold][scaffold], [generated guide][starter] | `--output` defaults to `modules/<name>` under the current directory. The runtime checkout ignores its own `modules/` directory. `--module-path` defaults to `example.com/<name>`, and `--sdk-path` defaults to the current directory, which must be a suitable checkout. A module outside the checkout has no repo-relative Make command. If the module and SDK move independently, its Go replacements can break. | Automate · P2 | Check the chosen paths before the final review and show the actual buildable path or explain the limitation. Do not move a source tree, overwrite an existing directory, or silently select a different SDK. |
| M3 [Archive build][build], [starter][starter] | `make modules MODULE=hello` produces and prints `bin/modules/hello/module.oci.tar`. The author runs `module install` separately; the generated README already supplies that command. `MODULE` is required. Examples outside `modules/` use checkout-relative paths. | Automate · P2 | Print a safely quoted next command for the exact successful artifact and target. Do not execute it, pick the newest archive, publish to a registry, or start a module as a build side effect. |
| M4 [Installer][module-install], [install UI][module-cli] | `module install <oci-archive>` hashes the selected local bytes and prepares them in a bounded, networkless guest. First use asks separately about runtime setup and module installation. Preparation precedes final approval. | Retain · P1 | Show what each approval changes. A decline never publishes or starts the module. It can retain already approved setup and reusable staged bytes charged to cache, including on an existing installation. Inspection alone does not identify a publisher or authorize launch. |
| M5 [Module options][module-install], [review][review] | The verified declaration can supply the module name. Guest UID/GID default to `1000`; custom modules can need explicit `--module-config` and `--approval`, even `{}` for settings. Local install permits `NONE` egress only. | Automate · P2 | Explain exactly which input is missing and show known safe defaults as proposals. Do not turn optional requests or `allResources` into grants, infer settings the image does not declare, or enable network access to make installation succeed. |
| M6 [Installer][module-install], [candidate generation][configure] | Installation refuses duplicate declaration names or module IDs. Installing while the runtime owns the writer lock points to `chatanium stop`. Rebuilding the archive does not replace the installed module. | Combine · P2 | Distinguish adding a new module from the stopped candidate/configuration path for a changed module. State which operation needs downtime and review. No implicit stop, overwrite, hot reload, reset, or automatic restart. |
| M7 [Module CLI][module-cli], [backend setup][discord-install], [starter][starter], [live ACL command][live-acl] | Before `1043429394`, starter setup could ask for four numeric IDs. The new flow asks only for a bot token if there is no compatible managed backend. The owner selects resources by name after startup; a new starter has no access until then. | Resolved separately | This is the approved baseline, not a new candidate. Do not reintroduce numeric ID entry or an install-time resource grant. Existing approved configurations do not silently change. |
| M8 [Starter guide][starter], [credential handling][discord-install] | The Discord message starter also needs a bot in the guild, `GUILDS`, `GUILD_MESSAGES`, privileged `MESSAGE_CONTENT`, and channel view/send permissions. Interactive token input is hidden; the file alternative is owner-only. | Combine · P1 | Put Discord-side prerequisites in one checklist distinct from Chatanium authorization. Reuse a compatible backend; never replace its credentials during module install. Do not expose tokens in commands, logs, JSON, modules, or examples, or grant Discord permissions for the operator. |
| M9 [Ordinary example][general] | The ordinary example has its own settings, grants, scopes, and limits. It can require JSON with numeric Discord IDs. Its command path and the text-message starter have different intent needs. | Verify · P2 | Decide which example-specific inputs need better guidance. Do not present those settings as prerequisites for the token-only starter or enable optional operations by default. |
| M10 [Candidate validation][configure], [reset and purge][remove] | An initialized installation does not accept a zero-module candidate through the ordinary configuration path. Removing the final module from execution is therefore not the same operation as uninstalling the runtime or deleting its data. | Verify · P1 | Review a supported return-to-idle path that leaves persistent data intact. Treat removal from execution, cache reclamation, and persistent-data deletion as separate decisions. Do not route a request to disable the last module into reset or purge. |

#### Stage an image and review advanced configuration

| ID / evidence | Current step or burden | Disposition | Candidate and security retention |
|------|------|------|------|
| A1 [Source flags][image-cli], [image plan][prepare] | Standalone `prepare-image` takes a source kind, canonical absolute archive path or registry repository, and an exact digest. The archive digest covers all archive bytes; a registry digest names a manifest. | Combine · P2 | Show distinct examples for `oci-archive`, `docker-archive`, and `registry`. Translate a trusted registry reference into its HTTPS repository and separate digest for review, not a mutable tag. Computing a local hash may compare bytes but must not manufacture a trusted expected value. |
| A2 [Registry policy][registry], [source flags][image-cli] | A registry may need an explicit `--registry-token-url`, service, and repeatable `--registry-redirect-host`. Hosts must be distinct and sorted. The registry repository is not the token endpoint or an unrestricted content origin. | Automate · P1 | Order already selected hosts and display the exact authority list before approval. Require independently authorized origins; no challenge, redirect, image, or failed fetch can add one. Keep HTTPS/public-address checks and do not forward a registry bearer token to a blob redirect host. |
| A3 [Preparation bounds][prepare], [plan checks][image-plan], [summary][review] | Defaults avoid a limits file. An override is a complete strict JSON object, including a deadline in nanoseconds. Installation budget, peak preparation/cache space, and module CPU, RAM, PID, persistent, and scratch limits mean different things. | Automate · P2 | Show units, the default values, and which bound failed before asking for another plan. Preserve every finite bound. Do not auto-increase disk, reserve host space, or present guest limits as a cap on the host worker. |
| A4 [Image CLI][image-cli], [configuration CLI][config-cli], [candidate][configure] | `prepare-image` returns a staged image ID. `generate-config` needs that ID, stable module ID, settings and grants files; guest UID/GID have defaults. Public egress needs its explicit network profile. The result goes to stdout. | Combine · P2 | Carry the reviewed image ID and show the next inputs together. Keep a candidate editable and unapproved, use protected canonical input paths, and keep the default at `NONE`. Staging is not activation. |
| A5 [Configuration and digest binding][configure], [review summaries][review], [CLI approvals][flags] | `configure --config` asks for the configuration `PlanDigest`, then each module's `ReviewDigest`. `planConfiguration` includes the ordered review digests; `configureCandidate` constructs the complete stopped revision before review. The terminal summary can abbreviate capability lists. | Combine · P1 | Consider one final human `[y/N]` for that revision only if the complete plan, every changed grant, and every retained scope are reviewable before the answer. Bind it to the same `PlanDigest` and all constituent `ReviewDigest` values. Keep per-module validation and ordered machine approvals. A count, truncated list, or blanket yes does not qualify. |
| A6 [Inspect and generate][config-cli], [candidate format][configure] | `inspect-config` writes the exact installed configuration. It is not the `generate-config` wrapper containing `prepared_images` and `network_profiles`, nor a list of running modules. | Retain · P3 | Label each document by purpose. Preserve exact machine-readable bytes and read-only inspection, without adding a confirmation or printing secret values as explanatory output. |

#### Stop, maintain, delete, and restore

| ID / evidence | Current step or burden | Disposition | Candidate and security retention |
|------|------|------|------|
| L1 [Stop][stop], [service events][results] | Ctrl+C or `chatanium stop` stops the foreground runtime. `stop` records stopped intent before waiting for the owner; that intent alone is not proof of worker exit or scratch cleanup. | Retain · P1 | Say whether stop was requested or cleanup was confirmed. If `CLEANUP_PENDING` remains, retain charges and evidence. Never report success from a missing socket, PID, or free lock. |
| L2 [Reset command][reset-cmd], [reset scope][reset], [summary][review] | On an existing stopped installation, `init` and its alias `reset` can erase configuration, cache, module data, and backups, then recreate the installation. The default answer is no, including in JSON-plan mode. | Retain · P1 | Show the exact deletion and replacement scope under either spelling. Keep refusal on a live or uncertain installation and separate any module decision. Never advise `init` as a harmless retry or use `--approve` to answer the reset question. |
| L3 [Update][update], [review][review], [results][results] | A stopped update to a different compatible bundle backs up the prior configuration and data, changes installed code, and clears active module approvals for fresh review. A verified same-bundle update does not request a new plan. | Retain · P1 | Retain approval of the exact target and backup scope. R9 would replace typing its digest, not the update decision or the manifest and backup checks. Show the need for re-review before consent; do not reactivate old grants or add a no-op prompt. |
| L4 [Removal][remove], [results][results] | `uninstall` removes installed code but keeps configuration, cache, module data, backups, and ledger charges. It does not have a purge-style approval prompt. | Retain · P2 | Keep the existing retained-data message. Distinguish it from `purge` before the user picks a command. No implicit deletion to reclaim space. |
| L5 [Purge][remove], [summary][review] | `purge` reviews the actual deletion inventory and exact digest. It leaves the shared parent and downloaded executable. Interrupted deletion uses persisted state and a terminal receipt. | Retain · P1 | R9 would change how a human confirms the exact inventory, not which files may be removed. Show removed and retained items and keep scope checks before and after confirmation. Resume only under matching recorded authority; never interpret a generic yes as permission to purge. |
| L6 [Update output][maintenance-cli], [restore guide][portable], [binding][restore] | Restore needs the backup ID and a trusted hash of the original `inventory.json`; the update result envelope lists manifest state and digests, not that pair. Files must be staged privately at the approved path with matching verified code. | Combine · P1 | Explain when to save the trusted receipt separately and group the member-copy and `bind-restored-volumes` steps. Unlike R9, `--receipt-digest` authenticates an external copy: keep it mandatory even in a terminal. Neither yes/no nor a digest calculated from the restored copy can replace it. No live overlay or arbitrary volume import. |
| L7 [Restore guide][portable], [backend secret][discord-install] | Backups omit host credentials. Restored Discord configuration can refer to the private managed token file, which must be supplied separately without a trailing newline. | Retain · P2 | Explain missing-secret recovery separately from successful volume binding. Do not bundle secrets into the backup, relax file permissions, or read a token from an unrelated account or module. |
| L8 [Recovery][recovery], [legacy rejection][flags], [path rules][paths] | Busy, damaged, foreign, cleanup-pending, and legacy installations need different actions. Selected old flags and hidden service/development commands reject portable use. | Combine · P2 | Index errors by the next *safe* action: contact the foreground owner, inspect with the matching launcher, or use the original legacy launcher as applicable. If there is no proven recovery action, say what evidence is missing. No force-unlock, cleanup bypass, or migration by retry. |

#### Build, develop, and qualify a release

| ID / evidence | Current step or burden | Disposition | Candidate and security retention |
|------|------|------|------|
| B1 [Build guide][build-guide], [tool discovery][common], [runtime build][runtime-build] | Go is pinned; `BOOTSTRAP_GO` can select a compiler, and portable packaging verifies GVX with a protected `gh` executable (`TRUSTED_GH` override). Wrong tool, host, or target blocks a build. | Automate · P2 | Identify the selected paths, target, and failed prerequisite early. Keep the compiler/version and verifier trust checks; do not install packages, alter ownership, or make these source-build requirements of people running a verified launcher. |
| B2 [Make targets][make], [build driver][build], [SDK guide][sdk-guide] | The guide lists `make tools`, `prepare-sdk`, `build`, `buf`, and `buf-check` together. Repository builds prepare the SDK where needed. Direct Go consumers of a local replacement must coordinate preparation and a shared reader lease. | Remove · P2 | Drop redundant manual preparation and generator steps from the ordinary build recipe, not from paths that actually need them. Preserve the upstream checksums, patch verification, immutable generation, and lock order; do not prepare while holding a reader lease. |
| B3 [Makefile][make], [build selection][build], [archive packer][packer] | `make build` and `make build-runtime` build the launcher, not module executables. `build-module <directory>` produces an executable; `modules MODULE=…` produces an OCI tar. A positional directory matching a Make target needs a prefix such as `modules/`. | Combine · P2 | Offer an artifact chooser with exact output paths, architecture, and explicit example/fixture selection. Never execute a Make goal as a module argument, an executable as an installed module, or a host binary as a guest of the wrong architecture. |
| B4 [Source catalog][catalog], [discovery][common] | `make list-module` reads direct module manifests. The footer says `N/A Activated` and counts plugins “installed locally”; it counts discovered source directories, not installed or active modules. | Remove · P3 | Remove that implication from the wording. Preserve offline discovery, required/optional request labels, and terminal-safe metadata. Do not query a live runtime or imply grants just to populate the footer. |
| B5 [Makefile][make], [build guide][build-guide] | `make serve` aliases `make run`, which requires a matching local portable build and rejects `CONFIG` or dev mode. `make new_module` uses the built local portable launcher by default or a launcher explicitly selected through `RUNTIME`. | Resolved separately | The fixed launcher path is gone. Preserve explicit launcher selection and keep production hot reload out of this path. |
| B6 [Image producer][images], [image guide][image-guide] | `image-module` requires `MODULE_IMAGE`. The Docker build tags locally; `.tools/images/<module-directory>/image.json` records a local ID, not a published RepoDigest. | Combine · P2 | Keep local build, authorized publication, and immutable digest selection separate. Never push by default, pick a writable registry for the user, or install from a mutable tag. |
| B7 [Image recipes][images], [OCI packer][packer], [portable guide][portable] | Docker image packaging applies the portable resource label only to known matching module recipes. The ordinary local archive packer emits the label. A custom author's choice of target therefore matters even when both builds produce OCI content. | Verify · P2 | State which path produces an installable artifact for a custom module; verify the exact recipe and target before offering a registry shortcut. Do not add a label to an unverified image to get past preparation. |
| B8 [Build guide][build-guide], [native build][voice-build] | `build-native` checks the legacy host ABI, loader, and licenses. It requires Linux/amd64, BuildKit, pinned tools, and a workspace under `/home`. The ordinary archive path does not. `DISABLE_VOICE=0` does not give a portable bundle a verified native voice closure. | Automate · P2 | Preflight only the selected path. Keep native provenance, ABI checks, license files, and explicit build concurrency. Do not install development tools on a runtime host, widen egress, or treat compilation as playback evidence. |
| B9 [Makefile][make], [legacy guide][legacy-dev], [watcher][watch], [SDK guide][sdk-guide] | The legacy guide uses `run-legacy-dev` with `LEGACY_RUNTIME`; `build-dev-worker` also requires that launcher selection. The SDK guide describes portable GVX launch. | Resolved separately | Keep the historical Linux path opt-in with its protected launcher and existing authorization. Never direct a portable user to install a host service or loosen a socket ACL. |
| B10 [Protocol maintenance][proto], [Makefile][make], [build guide][build-guide] | `make tools` installs pinned Buf/plugins under `.tools/bin`; `buf` publishes owned files, `buf-check` compares. An SDK policy change has an ordered extraction/generation sequence. SQL schema edits separately need `sqlc` v1.30.0 and three generated Go files. | Combine · P3 | Index commands by the input changed. Keep generation separate from comparison, preserve owned outputs and pins, and do not regenerate unrelated code during an ordinary build. |
| B11 [Offline checks][offline], [integration runner][integration], [scenarios][scenarios] | `build-integration` builds the legacy runner without running it. `check-offline` checks the prepared SDK and tracked Go packages without testing independent module sources under `modules/`. `check-sandbox-policy` requires the installed runner plus a separately installed observer, an approved plan, and a private evidence directory. | Retain · P2 | Say what each check establishes. Do not require an observer or credentials for an ordinary module. Keep timeouts, explicit image preparation, and the ownership checks on the runner and evidence. |
| B12 [Scenario wrapper][scenarios], [runner][integration], [validation guide][validation] | The guide identifies `check-sandbox`, `smoke-discord`, and `smoke-voice` as legacy scenarios and includes `RUNTIME` and `INTEGRATION`. They still invoke legacy `start --foreground --installation-id`. Portable native release qualification is separate. Discord and voice also need an approved backend, actions, and where applicable participants. | Documentation corrected | Keep the launcher, runner, and prerequisites explicit. The documented commands do not establish delivery, isolation, or encrypted playback without observed evidence. |
| B13 [Clean][build], [native recovery][legacy-dev] | `make clean` removes owned binaries and directory-derived module artifacts, not all `.tools` state, native bundles, or Docker images. An interrupted native build can retain a receipt and block another build. | Retain · P3 | Show what is retained and why. Do not prune unrelated Docker state, delete leased SDK generations, or erase a cleanup receipt to make a retry work. |
| B14 [Release workflow][release], [native gate][qualification] | Release candidates cross-build on Linux. The workflow checks the exact candidate on its native target and publishes only targets whose evidence verifies, with a manifest, SBOM, acceptance receipt, and attestation bundle. An expected asset can be absent. | Retain · P1 | Explain a withheld target instead of recommending another architecture or an unattested build. Keep product attestation separate from GVX provenance. A controlled qualification fixture is not an approval script for arbitrary operator plans. |

## 5. API Design

### 5-1. New / Modified

None. No REST API, Go function, CLI flag, control verb, output schema, or error code changes. The following are current interaction contracts, not hypothetical commands.

| Task | Sequence to preserve |
|------|------|
| First module in a checkout | `./bin/chatanium new` → choose Local check, enter `hello`, review `modules/hello` → `make modules MODULE=hello` → `./bin/chatanium module install ./bin/modules/hello/module.oci.tar` → review initial runtime setup if needed, then the module → `./bin/chatanium serve`. The runtime repository ignores the module's sources. An operator with an existing archive starts at `module install`, without a checkout or compiler. |
| Separate review | On a stopped, initialized installation, `prepare-image` stages and returns an ID → `generate-config` emits a candidate → `configure --config` reviews the stopped configuration and each module → `serve` starts it. `inspect-config` reads the installed document, not the full candidate wrapper. This path does not return an established revision to zero modules (M10). |
| Ordinary and scripted approvals | Setup in `serve`/`init` uses yes/no unless `--json-approvals` or explicit `--approve` selects digests. Existing-installation reset still requires yes/no. `module install` uses yes/no in its interactive mode and exact plan digests otherwise. Standalone `prepare-image`, `configure`, `update`, and `purge` require exact digests when approval is needed. `--json` is not consent; plan/prompt text on stderr is not the result stream. |
| New Discord starter (separate delivery) | `module install <oci-archive>` → supply a token only if required and approve capabilities → `serve` → from another terminal as the same owner, `acl set <module>` → choose scope and review before/after. `acl show <module>` reads without changing it. Existing installations are not migrated by this proposal. |

**Draft interaction choices, not current behavior.** R9 changes only how the installation owner confirms a guarded plan in a human terminal. For example, `prepare-image` would show the source, exact expected digest, registry authorities if any, limits, and staging scope, then ask `Prepare only this image? [y/N]`. A yes would authorize only that plan. The result would still identify a staged image, not a published configuration. `update` would name the target, backup, and lost active approvals; `purge` would name the exact deletion inventory and retained items before a separate destructive question. Show readable facts by default, with complete details available before answering; raw plan JSON remains opt-in for human review. Do not feed prompt output back to stdin.

A5 is a separate choice about the number of human confirmations. For `configure --config`, first show the exact stopped revision and all modules it will retain, change, add, or remove. Make each image, setting, changed grant, retained resource scope, limit, and egress policy inspectable in readable form. Show credential references, never secret values. Only then would `Publish this stopped configuration? [y/N]` authorize that one configuration digest and its ordered module review digests together. If the interface cannot present a complete combined review, keep separate complete reviews or refuse publication. If the guarded revision changes, discard the answer and require review of the new plan. No response starts a module, authorizes a later invocation, or approves an unrelated plan.

Neither choice changes the scripted contract: exact expected digests still come from a separately reviewed plan in the required order. If any of stdin, stdout, and stderr is redirected, do not accept a human yes/no as guarded plan approval. An external restore receipt is still required wherever applicable. Open decisions are which commands should drop human digest transcription; whether `configure` meets the conditions for a combined review; whether a printed command suffices for M3; and where to remind the operator to retain the receipt (L6). Before implementation, present each selected command, prompt, expected streams, cancellation, and failure sequence for operator approval.

### 5-2. Error Handling

No new error contract. For future wording, report what failed, what has or has not changed, and one safe action where one is known.

- **Busy or incomplete:** A busy offline install can point to `chatanium stop`. `INITIALIZING`, `UNINSTALLED`, and `CLEANUP_PENDING` are not interchangeable. Do not report stopped, recreate a damaged install, or promise a safe retry without the corresponding evidence.
- **Declined module install:** No configuration was published. An already approved base installation and prepared bytes may remain. If space cleanup is needed, name the retained state and its scope before offering any removal action.
- **Input or approval mismatch:** Identify the offending file, field, bound, or approval stage without echoing secrets. An unacceptable path, stale digest, changed candidate, or unapproved registry origin requires corrected inputs or fresh review. Under R9 and A5, `n`, empty input, EOF, or an incomplete review leaves the action unauthorized. A changed digest invalidates a prior yes. Do not silently repair policy.
- **Discord unavailable or denied:** Distinguish backend setup, Discord permissions/intents, the installed capability ceiling, and live policy. Under the approved baseline, unresolved identity or scope stays denied. Do not ask for numeric IDs to proceed, broaden the grant, or suggest Administrator permission.
- **Wrong tool, target, or receipt:** Point to the applicable build or download path, or the independently saved matching receipt. If native evidence, publisher trust, or a trusted backup receipt is missing, do not claim success.

## 6. Implementation Plan

### 6-1. Milestones

These are review milestones. No implementation is authorized here; estimates and owners for later work have not been assigned.

| Phase | Task and exit condition | Estimated Duration | Owner |
|------|------|------|------|
| 1. Inventory | Record current steps, evidence, and security retention for all command families above; distinguish source facts from proposed changes. Deliverable: this draft. | Not estimated | Unassigned |
| 2. Consistency review | Independently check the inventory against the primary checkout. Reconcile M7 with the separate ACL delivery and distinguish remaining example-specific inputs in M9. Completed for this draft; the remaining choices need operator review. | Not estimated | Unassigned |
| 3. Operator choice | For selected findings only, show the ordered interaction for terminal and scripted use, including refusal and recovery. Record which, if any, the operator approves for a separate change. Depends on the applicable evidence from phase 2. | Not estimated | Unassigned |
| 4. Acceptance of a later change | Only after separate approval and implementation, check the applicable predicates below on the intended artifact. Record observed outcomes and untested cases. A documentation-only selection needs a walkthrough, not a new runtime feature. | Not estimated | Unassigned |

Validation predicates for that review; none were executed in this audit:

1. **First success:** A release user can identify and independently authenticate the correct asset, run `serve` as the owner, and distinguish an idle installation from a running module. A local author can identify the exact archive to review without Docker, a registry, or Discord credentials. Neither path changes the host to meet a prerequisite.
2. **Consent and output:** For R9, a human can approve a complete review without copying its digest; a changed plan cannot reuse the answer. For A5, one yes can publish exactly one stopped revision only when each changed grant and retained scope is reviewable and all constituent digests match. With stdin piped but stdout and stderr on terminals, no `y` can confirm a guarded plan, including purge. Scripts still supply ordered expected digests and get results separately from diagnostics. Declining reset leaves data intact. Declining module publication can retain independent setup and staged bytes, but cannot install or start the module.
3. **Acquisition and policy:** Changing an archive, registry origin, grant, resource bound, or deletion scope cannot inherit the old approval. A candidate cannot start a module. A registry-supplied challenge or redirect cannot expand the operator's authority list.
4. **Approved Discord baseline, checked separately:** A new Discord starter accepts the required host credential without numeric Discord ID entry and reviews capability ceilings only. It denies resource access until the owner grants it via the live ACL. An ACL cannot exceed installed grants, unrelated channels stay denied, and a non-owner cannot change it over the socket. Previously approved modules keep their existing scope until explicitly opted in. A module never receives the bot token, and the CLI does not print it.
5. **Maintenance:** Stopping with uncertain cleanup does not claim success. A real code update leaves the operator able to identify the backup and need for re-review. Uninstall retains data; purge or reset lists the deletion scope. A restore lacking the separately trusted receipt or matching members cannot bind volumes.
6. **Developer evidence:** Each recipe names its input, artifact, and target. A source listing does not claim installation; a local tag does not claim publication; a cross-build does not claim native qualification. A missing prerequisite or participant cannot become a passing live smoke result.

### 6-2. Dependencies

The inventory adds no runtime or build dependency. A later choice about wording depends on the integrated CLI and operator review. Native and live acceptance, if relevant to a separately approved change, need the appropriate verified launcher, native target, private test installation, and explicitly authorized external resources. Do not use the operator's active installation or a production bot to validate this document.

Coverage limits: source and documentation were inspected; no product command, build, test, generator, registry fetch, or Discord session was run. Platform ACLs, terminal rendering and accessibility, real download availability, provider error variants, message delivery, and voice playback were not exercised. The inventory covers the named public CLI and Make command families, generated onboarding, example contracts, release workflow, and legacy distinctions. It is not an exhaustive list of internal flags, SDK operations, SQLite recovery branches, shell completions, plugin behavior, or third-party UI screens.

## 7. References

- [Product concept][concept], [repository conventions](../../AGENTS.md), [portable operator guide][portable], and [portable-v2 design](CHAT-1.md).
- [Launcher commands][root], [setup][setup], [module install][module-install], [configuration review][configure], [restore command][maintenance-cli], and the per-row source links above.
- [Scaffolding][scaffold], [generated module guide][starter], [public SDK][sdk-guide], [protocol maintenance][proto], and the [ordinary example][general].
- [Make targets][make], [pinned-build guide][build-guide], [release workflow][release], [native acceptance][qualification], and [integration entry points][integration]. Historical Linux instructions describe the original launcher only.

[concept]: ../../CONCEPT.md
[portable]: ../../README.md#run-a-portable-installation
[build-guide]: ../../README.md#pinned-builds-and-independent-artifacts
[author-guide]: ../../README.md#create-a-v2-module
[image-guide]: ../../README.md#module-images
[legacy-dev]: ../../README.md#development-only-hot-reload
[validation]: ../../README.md#generic-modules-scopes-and-validation-boundaries
[release]: ../../.github/workflows/release.yml
[qualification]: ../../tools/build/nativeacceptance/gate.py
[root]: ../../internal/cli/root.go
[flags]: ../../internal/cli/portable.go
[image-cli]: ../../internal/cli/portable_image.go
[config-cli]: ../../internal/cli/portable_config.go
[maintenance-cli]: ../../internal/cli/portable_maintenance.go
[terminal]: ../../internal/cli/portable_ui.go
[results]: ../../internal/cli/portable_results.go
[setup]: ../../internal/cli/portable_setup.go
[setup-approval]: ../../internal/cli/portable_setup_approval.go
[reset-cmd]: ../../internal/cli/portable_reset.go
[module-cli]: ../../internal/cli/module.go
[live-acl]: ../../internal/cli/acl.go
[new]: ../../internal/cli/new.go
[tui]: ../../internal/cli/tui/newcmdinput/newcmdinput.go
[scaffold]: ../../internal/scaffold/scaffold.go
[starter]: ../../internal/scaffold/templates/README.md.tmpl
[paths]: ../../internal/portable/install/paths.go
[init]: ../../internal/portable/install/init.go
[activation]: ../../internal/portable/install/serve.go
[module-install]: ../../internal/portable/install/module_install.go
[discord-install]: ../../internal/portable/install/module_discord.go
[prepare]: ../../internal/portable/install/prepare.go
[image-plan]: ../../internal/portable/images/plan.go
[registry]: ../../internal/portable/images/registry.go
[configure]: ../../internal/portable/install/configure.go
[review]: ../../internal/portable/install/setup_review.go
[stop]: ../../internal/portable/service/control.go
[reset]: ../../internal/portable/install/reset.go
[update]: ../../internal/portable/install/maintenance_update.go
[remove]: ../../internal/portable/install/maintenance_remove.go
[restore]: ../../internal/portable/install/restore.go
[recovery]: ../../internal/portable/install/maintenance_recovery.go
[make]: ../../Makefile
[common]: ../../tools/common.sh
[build]: ../../tools/build.sh
[packer]: ../../tools/build/module_oci.py
[catalog]: ../../tools/list-modules.py
[images]: ../../tools/build/images.py
[runtime-build]: ../../tools/build/runtime.sh
[voice-build]: ../../tools/build/voice.sh
[watch]: ../../tools/dev/watch.py
[offline]: ../../tools/build/check-offline.sh
[scenarios]: ../../tools/build/scenario.sh
[integration]: ../../tests/integration/legacy/main.go
[proto]: ../../proto/README.md
[sdk-guide]: ../../shared/README.md
[general]: ../../examples/general-bot/README.md
