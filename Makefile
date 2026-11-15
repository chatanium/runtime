include tools/versions.mk

.DEFAULT_GOAL := build
GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0
BUILD_JOBS ?= 2
MODULE ?= examples/general-bot
DISABLE_VOICE ?= 0
export GOOS GOARCH CGO_ENABLED GO_TOOLCHAIN BUF_VERSION PROTOC_GEN_GO_VERSION PROTOC_GEN_GO_GRPC_VERSION
export BUILD_JOBS MODULE DISABLE_VOICE MODULE_IMAGE MUSIC_IMAGE PLAYER_IMAGE
export CONFIG SUPERVISOR_SOCKET SUPERVISOR_UID SUPERVISOR_MAX_BYTES CHECK_DEADLINE TEST_TIMEOUT OBSERVE RUNTIME
export INTEGRATION POLICY_PLAN POLICY_RUNNER EVIDENCE

# Only fixed host/integration outputs are catalogued. Module sources and output
# paths are discovered and validated by tools/common.sh.
RUNTIME_TARGETS := .:.:bin/chatanium .:./cmd/flexmodule-supervisor:bin/flexmodule-supervisor
BUILD_OUTPUTS := bin/chatanium bin/flexmodule-supervisor \
	bin/flexmodule-integration bin/flexmodule-runtime-return-holder

# Explicit ownership covers only current v2 generated outputs. The completed
# cutover removed legacy schemas, generated files and wrappers.
GENERATED_EXPECTED_FILES := core-v2/core.pb.go core-v2/core_grpc.pb.go \
	discord-v2/domain.pb.go discord-v2/events.pb.go \
	discord-v2/helper.pb.go discord-v2/helper_grpc.pb.go \
	discord-v2/ownership.pb.go discord-v2/ownership_grpc.pb.go \
	discord-v2/voice.pb.go discord-v2/voice_grpc.pb.go
GENERATED_FILES := $(GENERATED_EXPECTED_FILES)
export GENERATED_FILES GENERATED_EXPECTED_FILES BUILD_OUTPUTS

MAKE_COMMAND_TARGETS := tools prepare-sdk build build-runtime build-module build-native build-integration buf buf-check clean run \
	sqlc start new_module list-module image-module image-media check-offline check-sandbox check-sandbox-policy smoke-discord smoke-voice
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

# Full native voice runtime by default; static runtime is an explicit opt-out.
build-runtime:
	@if [ "$$DISABLE_VOICE" = 1 ]; then \
		CGO_ENABLED=0 bash tools/build.sh build $(RUNTIME_TARGETS); \
	else \
		CGO_ENABLED=1 bash tools/build/voice.sh && \
		CGO_ENABLED=0 bash tools/build.sh build .:./cmd/flexmodule-supervisor:bin/flexmodule-supervisor; \
	fi

# Build every direct, non-symlink v2 module, without a per-module target catalog.
build: build-runtime
	@bash tools/build.sh modules

build-module:
	@bash tools/build.sh module "$$MODULE_BUILD_DIRECTORY"

# Inspect canonical manifests only; no compiler, native runtime or SDK is needed.
list-module:
	@bash -euo pipefail -c 'source tools/common.sh; \
		directories=(); discovered=$$(list_module_directories); \
		if [[ -n "$$discovered" ]]; then mapfile -t directories <<< "$$discovered"; fi; \
		exec python3 tools/list-modules.py "$${directories[@]}"'

# Permanent ordinary/no-voice harness and same-package runtime return holder.
build-integration:
	@CGO_ENABLED=0 bash tools/build.sh build .:./tests/integration:bin/flexmodule-integration
	@CGO_ENABLED=0 bash tools/build.sh test-binary .:./internal/app:bin/flexmodule-runtime-return-holder

# Native C++/ABI/loader/license gate only; independent of unfinished app Go.
build-native:
	@bash tools/build/voice.sh native


image-module:
	@test -n "$(MODULE_IMAGE)" || { echo 'Set MODULE_IMAGE to an explicit writable OCI tag' >&2; exit 1; }
	@CGO_ENABLED=0 bash tools/build.sh module "$$MODULE"
	@CGO_ENABLED=0 bash tools/build/images.sh module

image-media:
	@test -n "$(MUSIC_IMAGE)" -a -n "$(PLAYER_IMAGE)" || { echo 'Set MUSIC_IMAGE and PLAYER_IMAGE to explicit writable OCI tags' >&2; exit 1; }
	@CGO_ENABLED=0 bash tools/build/images.sh build-media-modules
	@CGO_ENABLED=0 bash tools/build/images.sh media

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

run: build-runtime
	@./bin/chatanium start --config "$(CONFIG)" --supervisor-socket "$(SUPERVISOR_SOCKET)" \
		--supervisor-uid "$(SUPERVISOR_UID)" --supervisor-max-bytes "$(SUPERVISOR_MAX_BYTES)"

# Existing Chatanium database generation remains separate from protocol generation.
sqlc:
	@sqlc generate -f database/sqlc.yaml

start: run

new_module: build-runtime
	@./bin/chatanium new
