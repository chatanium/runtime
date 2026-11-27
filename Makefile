include tools/versions.mk

.DEFAULT_GOAL := build
GOOS ?= linux
HOST_GOARCH := $(subst aarch64,arm64,$(subst x86_64,amd64,$(shell uname -m)))
GOARCH ?= $(HOST_GOARCH)
CGO_ENABLED ?= 0
BUILD_JOBS ?= 2
MODULE ?= examples/general-bot
DISABLE_VOICE ?= $(if $(filter build-dev-worker run-legacy-dev,$(MAKECMDGOALS)),0,1)
DEV_MODE ?= 0
DEV_SOCKET ?=
DEV_RUNTIME_USER ?=
LEGACY_RUNTIME ?=
export GOOS GOARCH CGO_ENABLED GO_TOOLCHAIN BUF_VERSION PROTOC_GEN_GO_VERSION PROTOC_GEN_GO_GRPC_VERSION
export BUILD_JOBS MODULE DISABLE_VOICE MODULE_IMAGE MUSIC_IMAGE PLAYER_IMAGE DEV_MODE DEV_SOCKET DEV_RUNTIME_USER LEGACY_RUNTIME
export CONFIG INSTALLATION_ID TRUSTED_GH CHECK_DEADLINE TEST_TIMEOUT OBSERVE RUNTIME
export INTEGRATION POLICY_PLAN POLICY_RUNNER EVIDENCE

# Only fixed host/integration outputs are catalogued. Module sources and output
# paths are discovered and validated by tools/common.sh.
BUILD_OUTPUTS := bin/chatanium bin/chatanium-worker bin/gvx-stage bin/gvx-guest-bridge bin/gvx-preparer \
	bin/flexmodule-integration

# Explicit ownership covers only current v2 generated outputs. The completed
# cutover removed legacy schemas, generated files and wrappers.
GENERATED_EXPECTED_FILES := core-v2/core.pb.go core-v2/core_grpc.pb.go \
	discord-v2/domain.pb.go discord-v2/events.pb.go \
	discord-v2/helper.pb.go discord-v2/helper_grpc.pb.go \
	discord-v2/ownership.pb.go discord-v2/ownership_grpc.pb.go \
	discord-v2/voice.pb.go discord-v2/voice_grpc.pb.go
GENERATED_FILES := $(GENERATED_EXPECTED_FILES)
export GENERATED_FILES GENERATED_EXPECTED_FILES BUILD_OUTPUTS

MAKE_COMMAND_TARGETS := tools prepare-sdk build build-runtime build-dev-worker build-module build-native build-integration buf buf-check clean run run-legacy-dev \
	sqlc serve new_module list-module image-module image-media check-offline check-sandbox check-sandbox-policy smoke-discord smoke-voice
.PHONY: $(MAKE_COMMAND_TARGETS)

# Make has no positional arguments: consume exactly one otherwise-unrecognized
# goal only for this API. Never swallow typos for ordinary Make invocations, or
# execute a real command such as clean as the alleged module directory.
ifneq ($(filter build-module,$(MAKECMDGOALS)),)
ifneq ($(firstword $(MAKECMDGOALS)),build-module)
$(error Use exactly: make build-module <directory>)
endif
ifneq ($(words $(MAKECMDGOALS)),2)
$(error Use exactly: make build-module <directory>)
endif
MODULE_BUILD_DIRECTORY := $(word 2,$(MAKECMDGOALS))
ifneq ($(filter $(MAKE_COMMAND_TARGETS),$(MODULE_BUILD_DIRECTORY)),)
$(error Module directory conflicts with a Make command; use modules/<name> explicitly)
endif
export MODULE_BUILD_DIRECTORY
.DEFAULT:
	@:
endif

tools:
	@bash tools/install-tools.sh

# Resolve and validate the pinned upstream source plus the maintained patch stack.
prepare-sdk:
	@bash -euo pipefail -c 'source tools/common.sh; use_go; run python3 tools/sdk.py --go "$$GO_BINARY"'

# Cross-build the portable-v2 launcher and its matching host/guest payload.
build-runtime:
	@bash tools/build/runtime.sh

# The v1 watcher can replace only the worker of an explicitly selected legacy installation.
build-dev-worker:
	@test -n "$$LEGACY_RUNTIME" || { echo 'Use build-runtime for portable-v2; a v1 worker build requires LEGACY_RUNTIME' >&2; exit 1; }
	@test "$$GOOS/$$GOARCH" = linux/amd64 || { echo 'The v1 worker archive supports Linux amd64 only' >&2; exit 1; }
	@if [ "$$DISABLE_VOICE" = 1 ]; then \
		GOAMD64=v2 GOENV=off CGO_ENABLED=0 bash tools/build.sh build .:./cmd/chatanium-worker:bin/chatanium-worker; \
	else \
		bash tools/build/voice.sh voice; \
	fi

# Build every direct, non-symlink v2 module, without a per-module target catalog.
build: build-runtime
	@GOOS=linux bash tools/build.sh modules

build-module:
	@GOOS=linux bash tools/build.sh module "$$MODULE_BUILD_DIRECTORY"

# Inspect canonical manifests only; no compiler, native runtime or SDK is needed.
list-module:
	@bash -euo pipefail -c 'source tools/common.sh; \
		directories=(); discovered=$$(list_module_directories); \
		if [[ -n "$$discovered" ]]; then mapfile -t directories <<< "$$discovered"; fi; \
		exec python3 tools/list-modules.py "$${directories[@]}"'

# Permanent ordinary/no-voice integration caller; no runtime execution.
build-integration:
	@CGO_ENABLED=0 bash tools/build.sh build .:./tests/integration:bin/flexmodule-integration

# Native C++/ABI/loader/license gate only; independent of unfinished app Go.
build-native:
	@bash tools/build/voice.sh native


image-module:
	@test -n "$(MODULE_IMAGE)" || { echo 'Set MODULE_IMAGE to an explicit writable OCI tag' >&2; exit 1; }
	@GOOS=linux CGO_ENABLED=0 bash tools/build.sh module "$$MODULE"
	@GOOS=linux CGO_ENABLED=0 bash tools/build/images.sh module

image-media:
	@test -n "$(MUSIC_IMAGE)" -a -n "$(PLAYER_IMAGE)" || { echo 'Set MUSIC_IMAGE and PLAYER_IMAGE to explicit writable OCI tags' >&2; exit 1; }
	@GOOS=linux CGO_ENABLED=0 bash tools/build/images.sh build-media-modules
	@GOOS=linux CGO_ENABLED=0 bash tools/build/images.sh media

check-offline:
	@bash tools/build/check-offline.sh

check-sandbox:
	@bash tools/build/scenario.sh sandbox

# Explicit installed root-side observer path; never privileged go-run.
check-sandbox-policy:
	@bash tools/build/scenario.sh sandbox-policy

smoke-discord:
	@bash tools/build/scenario.sh discord

smoke-voice:
	@bash tools/build/scenario.sh voice

buf:
	@bash tools/generate.sh publish

buf-check:
	@bash tools/generate.sh check

# Remove fixed host binaries and directory-derived module artifacts only.
# Native work/source/license archives and OCI images are intentionally retained.
clean:
	@bash tools/build.sh clean

# Start only a portable output built for this Linux host, not an old bin/chatanium.
PORTABLE_LOCAL := .tools/release/portable/linux-$(HOST_GOARCH)/chatanium-linux-$(HOST_GOARCH)
run:
	@test "$$DEV_MODE" = 0 || { echo 'Portable-v2 development: build-runtime, then use update after stopping. For v1 hot-swap use run-legacy-dev.' >&2; exit 1; }
	@test -z "$$CONFIG" || { echo 'Portable-v2 serve uses the reviewed installation configuration, not CONFIG' >&2; exit 1; }
	@test -x "$(PORTABLE_LOCAL)" || { echo 'Run build-runtime for the local portable-v2 launcher first' >&2; exit 1; }
	@./$(PORTABLE_LOCAL) serve

run-legacy-dev:
	@test -n "$$LEGACY_RUNTIME" || { echo 'Set LEGACY_RUNTIME to the existing v1 launcher' >&2; exit 1; }
	@DEV_MODE=1 python3 tools/dev/watch.py --runtime "$$LEGACY_RUNTIME" \
		--socket "$$DEV_SOCKET" --installation-id "$$INSTALLATION_ID"

# Existing Chatanium database generation remains separate from protocol generation.
sqlc:
	@sqlc generate -f database/sqlc.yaml

serve: run

new_module:
	@/usr/local/bin/chatanium new
