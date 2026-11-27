# Chatanium v2

Chatanium is a chatbot runtime for independently developed modules and online chat providers. Discord is the current optional backend. Module lifecycle, capability grants, storage and transport are defined by the backend-neutral `core-v2` protocol. A module receives typed events and approved helpers; it does not receive the host's Discord session or bot token.

## Operator experience

The release launcher bundles the pinned GVX `rungv` engine and matching helpers. Run `chatanium serve` as an ordinary user. On first use it shows the installation plan, requests approval and starts the worker in the foreground. Later runs reuse the same reviewed environment under the user's data directory. `doctor` is optional and read-only. On a stopped installation, `init` or its alias `reset` asks for confirmation before erasing managed configuration, image cache, module data and backups.

Keep common workflows short and predictable. Combine steps when the user has no decision to make between them. Keep checks and explicit approval where a step changes what can run, grants new access, or can destroy data.

Make everyday commands self-explanatory. Show progress in the terminal, put the important facts before confirmation, and give one concrete next action when something fails. Keep machine-readable output available for scripts. Before implementing a user-facing change, show the commands, prompts, and expected output in order, then get the operator's approval.

## Trust and resource boundaries

Modules run as nonroot executables from digest-pinned OCI images in separate GVX guests. Image preparation runs in a networkless guest, and the runtime binds each module's reviewed capabilities and resource limits to the verified image. GVX enforces guest CPU, memory and PID limits. Each module has a bounded persistent ext4lite image, and each instance gets scratch space that is discarded after use. These limits do not reserve host disk space or cap the host worker's resources. Network access is denied by default and can open only under a reviewed policy.

The portable runtime does not create host accounts or require a Docker daemon, host cgroups, host volume mounts or host firewall changes. The release bundles the engine for the target OS and architecture; any required hypervisor must already be available. The privileged Linux v1 runbooks are historical, not setup instructions for portable v2. See [the README](README.md) for build, target and operator details.
