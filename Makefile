include tools/versions.mk

.DEFAULT_GOAL := build
GOOS ?= linux
GOARCH ?= amd64
CGO_ENABLED ?= 0
BUILD_JOBS ?= 2
MODULE_KIND ?= general
export GOOS GOARCH CGO_ENABLED GO_TOOLCHAIN BUF_VERSION PROTOC_GEN_GO_VERSION PROTOC_GEN_GO_GRPC_VERSION
export BUILD_JOBS MODULE_KIND MODULE_IMAGE MUSIC_IMAGE PLAYER_IMAGE
export CONFIG SUPERVISOR_SOCKET SUPERVISOR_UID SUPERVISOR_MAX_BYTES CHECK_DEADLINE TEST_TIMEOUT OBSERVE RUNTIME
export INTEGRATION POLICY_PLAN POLICY_RUNNER EVIDENCE

# Runtime, general example, supervisor, and independent media modules.
# The prepared DiscordGo SDK is checked locally; upstream example releases are not owned here.
BUILD_TARGETS := .:.:bin/chatanium .:./examples/general-bot:bin/test-module .:./cmd/flexmodule-supervisor:bin/flexmodule-supervisor
MEDIA_TARGETS := modules/music-bot:.:bin/chatanium-musicbot modules/audio-player:.:bin/voice-player-module
MODULE_CHECK_TARGETS := .:./...:-
BUILD_OUTPUTS := bin/chatanium bin/test-module bin/flexmodule-supervisor bin/sandbox-module \
	bin/chatanium-musicbot bin/voice-player-module \
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

.PHONY: tools prepare-sdk build build-native build-voice build-media build-all build-sandbox build-integration buf buf-check clean run \
	sqlc start new_module image-module image-media check-offline check-sandbox check-sandbox-policy smoke-discord smoke-voice

tools:
	@bash tools/install-tools.sh

# Resolve and validate the pinned upstream source plus the maintained patch stack.
prepare-sdk:
	@bash -euo pipefail -c 'source tools/common.sh; use_go; run python3 tools/sdk.py --go "$$GO_BINARY"'

# Ordinary runtime, supervisor and bot; no native DAVE or media tool dependency.
build:
	@bash tools/build.sh build $(BUILD_TARGETS)

# Go compilation only; media programs are built into separate OCI images below.
build-media:
	@bash tools/build.sh build $(MEDIA_TARGETS)

build-all:
	@bash tools/build.sh build $(MODULE_CHECK_TARGETS) $(BUILD_TARGETS) $(MEDIA_TARGETS)

build-sandbox:
	@bash tools/build.sh build .:./tests/integration/fixtures/sandbox:bin/sandbox-module

# Permanent ordinary/no-voice harness and same-package runtime return holder.
build-integration:
	@CGO_ENABLED=0 bash tools/build.sh build .:./tests/integration:bin/flexmodule-integration
	@CGO_ENABLED=0 bash tools/build.sh test-binary .:./internal/app:bin/flexmodule-runtime-return-holder

# Native C++/ABI/loader/license gate only; independent of unfinished app Go.
build-native:
	@bash tools/build/voice.sh native

# Isolated EL9 source-patched native fork; all large work is bound under /home.
build-voice:
	@bash tools/build/voice.sh

image-module:
	@test -n "$(MODULE_IMAGE)" || { echo 'Set MODULE_IMAGE to an explicit writable OCI tag' >&2; exit 1; }
ifeq ($(MODULE_KIND),sandbox)
	@bash tools/build.sh build .:./tests/integration/fixtures/sandbox:bin/sandbox-module
else
	@bash tools/build.sh build .:./examples/general-bot:bin/test-module
endif
	@bash tools/build/images.sh module

image-media:
	@test -n "$(MUSIC_IMAGE)" -a -n "$(PLAYER_IMAGE)" || { echo 'Set MUSIC_IMAGE and PLAYER_IMAGE to explicit writable OCI tags' >&2; exit 1; }
	@bash tools/build.sh build $(MEDIA_TARGETS)
	@bash tools/build/images.sh media

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

# Removes only enumerated ordinary binaries. Native work/source/license archives
# and OCI images are intentionally retained; never prune shared Docker storage.
clean:
	@bash tools/build.sh clean

run: build
	@./bin/chatanium start --config "$(CONFIG)" --supervisor-socket "$(SUPERVISOR_SOCKET)" \
		--supervisor-uid "$(SUPERVISOR_UID)" --supervisor-max-bytes "$(SUPERVISOR_MAX_BYTES)"

# Existing Chatanium database generation remains separate from protocol generation.
sqlc:
	@sqlc generate -f database/sqlc.yaml

start: run

new_module: build
	@./bin/chatanium new
