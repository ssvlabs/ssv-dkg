# ==============================================================================
# SSV-DKG Makefile
# ==============================================================================
# Distributed Key Generation tool for SSV Network
# Supports multi-architecture builds (AMD64 + ARM64)
#
# Usage:
#   make help          - Show this help message
#   make build         - Build the binary
#   make test          - Run tests
#   make docker-build  - Build Docker image for current platform
#   make docker-multiarch - Build multi-arch Docker image
# ==============================================================================

# ------------------------------------------------------------------------------
# Configuration
# ------------------------------------------------------------------------------

# Shell configuration
SHELL := /bin/bash
.SHELLFLAGS := -eu -o pipefail -c
.DELETE_ON_ERROR:
MAKEFLAGS += --warn-undefined-variables
MAKEFLAGS += --no-builtin-rules

# Project metadata
PROJECT_NAME := ssv-dkg
BINARY_NAME := ssv-dkg
BINARY_PATH := ./bin/$(BINARY_NAME)

# Version detection (from git tags)
VERSION := $(shell git describe --tags $$(git rev-list --tags --max-count=1) 2>/dev/null || echo "dev")
GIT_COMMIT := $(shell git rev-parse --short HEAD 2>/dev/null || echo "unknown")
BUILD_TIME := $(shell date -u '+%Y-%m-%dT%H:%M:%SZ')

# Go configuration
GO ?= go
GOFLAGS := -v
LDFLAGS := -X main.Version=$(VERSION) -X main.GitCommit=$(GIT_COMMIT) -X main.BuildTime=$(BUILD_TIME)

# Docker configuration
DOCKER_IMAGE := ssv-dkg
DOCKER_REGISTRY ?= ssvlabs
DOCKER_TAG ?= $(VERSION)
DOCKER_PLATFORMS := linux/amd64,linux/arm64
DOCKER_BUILDER := ssv-dkg-builder

# Colors for terminal output
COLOR_RESET := \033[0m
COLOR_GREEN := \033[32m
COLOR_YELLOW := \033[33m
COLOR_BLUE := \033[34m
COLOR_CYAN := \033[36m

# ------------------------------------------------------------------------------
# Default target
# ------------------------------------------------------------------------------

.DEFAULT_GOAL := help

# ------------------------------------------------------------------------------
# PHONY declarations
# ------------------------------------------------------------------------------

.PHONY: help
.PHONY: build install clean
.PHONY: test lint lint-prepare critic critic-prepare gosec gosec-prepare deadcode deadcode-prepare
.PHONY: docker-build docker-multiarch docker-build-amd64 docker-build-arm64
.PHONY: docker-buildx-setup docker-push docker-clean
.PHONY: docker-demo-operators docker-demo-initiator docker-demo-ping
.PHONY: docker-demo-resign docker-demo-reshare docker-demo-ethnode
.PHONY: docker-operator docker-initiator
.PHONY: mockgen-install version info

# ==============================================================================
# Help
# ==============================================================================

## help: Show this help message
help:
	@printf "\n"
	@printf "$(COLOR_CYAN)$(PROJECT_NAME) - Makefile Commands$(COLOR_RESET)\n"
	@printf "\n"
	@printf "$(COLOR_GREEN)Build Commands:$(COLOR_RESET)\n"
	@printf "  build              Build the $(BINARY_NAME) binary\n"
	@printf "  install            Build and install to GOPATH/bin\n"
	@printf "  clean              Clean build artifacts and caches\n"
	@printf "\n"
	@printf "$(COLOR_GREEN)Test & Quality Commands:$(COLOR_RESET)\n"
	@printf "  test               Run all tests with gotestsum\n"
	@printf "  lint               Run golangci-lint\n"
	@printf "  lint-prepare       Install golangci-lint\n"
	@printf "  critic             Run go-critic\n"
	@printf "  gosec              Run security scanner\n"
	@printf "  deadcode           Find unused code\n"
	@printf "\n"
	@printf "$(COLOR_GREEN)Docker Commands:$(COLOR_RESET)\n"
	@printf "  docker-build       Build Docker image for current platform\n"
	@printf "  docker-multiarch   Build and push multi-arch image (amd64+arm64)\n"
	@printf "  docker-build-amd64 Build Docker image for AMD64\n"
	@printf "  docker-build-arm64 Build Docker image for ARM64\n"
	@printf "  docker-push        Push Docker image to registry\n"
	@printf "  docker-clean       Remove Docker builder and images\n"
	@printf "\n"
	@printf "$(COLOR_GREEN)Demo Commands:$(COLOR_RESET)\n"
	@printf "  docker-demo-operators  Run 13 demo operators\n"
	@printf "  docker-demo-initiator  Run demo initiator\n"
	@printf "  docker-demo-ping       Health check demo operators\n"
	@printf "\n"
	@printf "$(COLOR_GREEN)Other Commands:$(COLOR_RESET)\n"
	@printf "  version            Show version information\n"
	@printf "  info               Show build configuration\n"
	@printf "\n"
	@printf "$(COLOR_YELLOW)Variables:$(COLOR_RESET)\n"
	@printf "  DOCKER_TAG=$(DOCKER_TAG)\n"
	@printf "  DOCKER_REGISTRY=$(DOCKER_REGISTRY)\n"
	@printf "  DOCKER_PLATFORMS=$(DOCKER_PLATFORMS)\n"
	@printf "\n"

# ==============================================================================
# Build Commands
# ==============================================================================

## build: Build the Go binary
build:
	@printf "$(COLOR_BLUE)Building $(BINARY_NAME) $(VERSION)...$(COLOR_RESET)\n"
	@mkdir -p ./bin
	$(GO) build $(GOFLAGS) -o $(BINARY_PATH) -ldflags "$(LDFLAGS)" ./cmd/ssv-dkg/ssv-dkg.go
	@printf "$(COLOR_GREEN)Build complete: $(BINARY_PATH)$(COLOR_RESET)\n"

## install: Build and install binary to GOPATH/bin
install:
	@printf "$(COLOR_BLUE)Installing $(BINARY_NAME) $(VERSION)...$(COLOR_RESET)\n"
	$(GO) install $(GOFLAGS) -ldflags "$(LDFLAGS)" ./cmd/ssv-dkg/ssv-dkg.go
	@printf "$(COLOR_GREEN)Installation complete. Run '$(BINARY_NAME)' to launch.$(COLOR_RESET)\n"

## clean: Clean build artifacts and caches
clean:
	@printf "$(COLOR_BLUE)Cleaning build artifacts...$(COLOR_RESET)\n"
	$(GO) clean -cache
	rm -rf ./bin
	@printf "$(COLOR_GREEN)Clean complete$(COLOR_RESET)\n"

## version: Show version information
version:
	@echo "Version:    $(VERSION)"
	@echo "Git Commit: $(GIT_COMMIT)"
	@echo "Build Time: $(BUILD_TIME)"

## info: Show build configuration
info:
	@printf "$(COLOR_CYAN)Build Configuration:$(COLOR_RESET)\n"
	@printf "  Project:     $(PROJECT_NAME)\n"
	@printf "  Version:     $(VERSION)\n"
	@printf "  Go Version:  $(shell $(GO) version)\n"
	@printf "  Binary Path: $(BINARY_PATH)\n"
	@printf "\n"
	@printf "$(COLOR_CYAN)Docker Configuration:$(COLOR_RESET)\n"
	@printf "  Image:       $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)\n"
	@printf "  Tag:         $(DOCKER_TAG)\n"
	@printf "  Platforms:   $(DOCKER_PLATFORMS)\n"

# ==============================================================================
# Test & Quality Commands
# ==============================================================================

## test: Run all tests with gotestsum
test:
	@printf "$(COLOR_BLUE)Running tests...$(COLOR_RESET)\n"
	$(GO) run gotest.tools/gotestsum@latest \
		--format pkgname \
		--jsonfile test-output.log \
		-- -timeout=3600s ./...

## lint-prepare: Install golangci-lint
lint-prepare:
	@printf "$(COLOR_BLUE)Installing golangci-lint...$(COLOR_RESET)\n"
	curl -sSfL https://raw.githubusercontent.com/golangci/golangci-lint/master/install.sh | sh -s latest

## lint: Run golangci-lint
lint:
	@printf "$(COLOR_BLUE)Running linter...$(COLOR_RESET)\n"
	./bin/golangci-lint run -v ./...
	@if [ -n "$${UNFORMATTED:-}" ]; then \
		printf "$(COLOR_YELLOW)Some files require formatting. Run 'go fmt ./...'$(COLOR_RESET)\n"; \
		exit 1; \
	fi

## critic-prepare: Install go-critic
critic-prepare:
	@printf "$(COLOR_BLUE)Installing go-critic...$(COLOR_RESET)\n"
	$(GO) install -v github.com/go-critic/go-critic/cmd/gocritic@latest

## critic: Run go-critic
critic:
	@printf "$(COLOR_BLUE)Running go-critic...$(COLOR_RESET)\n"
	gocritic check -enableAll ./...

## deadcode-prepare: Install deadcode
deadcode-prepare:
	@printf "$(COLOR_BLUE)Installing deadcode...$(COLOR_RESET)\n"
	$(GO) install golang.org/x/tools/cmd/deadcode@latest

## deadcode: Find unused code
deadcode:
	@printf "$(COLOR_BLUE)Finding dead code...$(COLOR_RESET)\n"
	deadcode -test ./...

## gosec-prepare: Install gosec
gosec-prepare:
	@printf "$(COLOR_BLUE)Installing gosec...$(COLOR_RESET)\n"
	$(GO) install github.com/securego/gosec/v2/cmd/gosec@latest

## gosec: Run security scanner
gosec:
	@printf "$(COLOR_BLUE)Running security scan...$(COLOR_RESET)\n"
	gosec ./...

## mockgen-install: Install mockgen
mockgen-install:
	$(GO) install github.com/golang/mock/mockgen@v1.6.0
	@which mockgen || printf "$(COLOR_YELLOW)Error: ensure GOPATH/bin is in PATH$(COLOR_RESET)\n"

# ==============================================================================
# Docker Commands - Single Platform
# ==============================================================================

## docker-build: Build Docker image for current platform
docker-build:
	@printf "$(COLOR_BLUE)Building Docker image...$(COLOR_RESET)\n"
	DOCKER_BUILDKIT=1 docker build \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_IMAGE):latest \
		.
	@printf "$(COLOR_GREEN)Docker image built: $(DOCKER_IMAGE):$(DOCKER_TAG)$(COLOR_RESET)\n"

# ==============================================================================
# Docker Commands - Multi-Architecture
# ==============================================================================

## docker-buildx-setup: Setup Docker buildx for multi-arch builds
docker-buildx-setup:
	@printf "$(COLOR_BLUE)Setting up Docker buildx...$(COLOR_RESET)\n"
	@docker buildx inspect $(DOCKER_BUILDER) >/dev/null 2>&1 || \
		docker buildx create \
			--name $(DOCKER_BUILDER) \
			--driver docker-container \
			--platform $(DOCKER_PLATFORMS) \
			--bootstrap
	@docker buildx use $(DOCKER_BUILDER)
	@printf "$(COLOR_GREEN)Buildx ready: $(DOCKER_BUILDER)$(COLOR_RESET)\n"

## docker-multiarch: Build and push multi-architecture Docker image
docker-multiarch: docker-buildx-setup
	@printf "$(COLOR_BLUE)Building multi-arch image for: $(DOCKER_PLATFORMS)$(COLOR_RESET)\n"
	docker buildx build \
		--platform $(DOCKER_PLATFORMS) \
		--build-arg VERSION=$(VERSION) \
		--build-arg GIT_COMMIT=$(GIT_COMMIT) \
		--build-arg BUILD_TIME=$(BUILD_TIME) \
		-t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG) \
		-t $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest \
		--push \
		.
	@printf "$(COLOR_GREEN)Multi-arch image pushed: $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)$(COLOR_RESET)\n"

## docker-build-amd64: Build Docker image for AMD64 (x86_64)
docker-build-amd64: docker-buildx-setup
	@printf "$(COLOR_BLUE)Building AMD64 image...$(COLOR_RESET)\n"
	docker buildx build \
		--platform linux/amd64 \
		--build-arg VERSION=$(VERSION) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG)-amd64 \
		--load \
		.
	@printf "$(COLOR_GREEN)AMD64 image built: $(DOCKER_IMAGE):$(DOCKER_TAG)-amd64$(COLOR_RESET)\n"

## docker-build-arm64: Build Docker image for ARM64 (aarch64)
docker-build-arm64: docker-buildx-setup
	@printf "$(COLOR_BLUE)Building ARM64 image...$(COLOR_RESET)\n"
	docker buildx build \
		--platform linux/arm64 \
		--build-arg VERSION=$(VERSION) \
		-t $(DOCKER_IMAGE):$(DOCKER_TAG)-arm64 \
		--load \
		.
	@printf "$(COLOR_GREEN)ARM64 image built: $(DOCKER_IMAGE):$(DOCKER_TAG)-arm64$(COLOR_RESET)\n"

## docker-push: Push Docker image to registry
docker-push:
	@printf "$(COLOR_BLUE)Pushing Docker image...$(COLOR_RESET)\n"
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):$(DOCKER_TAG)
	docker push $(DOCKER_REGISTRY)/$(DOCKER_IMAGE):latest
	@printf "$(COLOR_GREEN)Image pushed to $(DOCKER_REGISTRY)/$(DOCKER_IMAGE)$(COLOR_RESET)\n"

## docker-clean: Remove Docker builder and local images
docker-clean:
	@printf "$(COLOR_BLUE)Cleaning Docker resources...$(COLOR_RESET)\n"
	-docker buildx rm $(DOCKER_BUILDER) 2>/dev/null || true
	-docker rmi $(DOCKER_IMAGE):latest 2>/dev/null || true
	-docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG) 2>/dev/null || true
	-docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG)-amd64 2>/dev/null || true
	-docker rmi $(DOCKER_IMAGE):$(DOCKER_TAG)-arm64 2>/dev/null || true
	@printf "$(COLOR_GREEN)Docker cleanup complete$(COLOR_RESET)\n"

# ==============================================================================
# Docker Demo Commands
# ==============================================================================

## docker-demo-operators: Run 13 demo operators locally
docker-demo-operators:
	@printf "$(COLOR_BLUE)Starting demo operators...$(COLOR_RESET)\n"
	docker-compose up --build \
		operator1 operator2 operator3 operator4 operator5 \
		operator6 operator7 operator8 operator9 operator10 \
		operator11 operator12 operator13

## docker-demo-initiator: Run demo initiator
docker-demo-initiator:
	@printf "$(COLOR_BLUE)Starting demo initiator...$(COLOR_RESET)\n"
	docker-compose up --build initiator

## docker-demo-ping: Health check demo operators
docker-demo-ping:
	@printf "$(COLOR_BLUE)Pinging demo operators...$(COLOR_RESET)\n"
	docker-compose up --build ping

## docker-demo-resign: Run re-sign ceremony demo
docker-demo-resign:
	@printf "$(COLOR_BLUE)Running re-sign ceremony demo...$(COLOR_RESET)\n"
	docker-compose up --build resign

## docker-demo-generate-resign-msg: Generate re-sign message
docker-demo-generate-resign-msg:
	@printf "$(COLOR_BLUE)Generating re-sign message...$(COLOR_RESET)\n"
	docker-compose up --build generate-resign-msg

## docker-demo-reshare: Run re-share ceremony demo
docker-demo-reshare:
	@printf "$(COLOR_BLUE)Running re-share ceremony demo...$(COLOR_RESET)\n"
	docker-compose up --build reshare

## docker-demo-generate-reshare-msg: Generate re-share message
docker-demo-generate-reshare-msg:
	@printf "$(COLOR_BLUE)Generating re-share message...$(COLOR_RESET)\n"
	docker-compose up --build generate-reshare-msg

## docker-demo-ethnode: Run local Ethereum node
docker-demo-ethnode:
	@printf "$(COLOR_BLUE)Starting Ethereum node...$(COLOR_RESET)\n"
	docker-compose up --build ethnode

# ==============================================================================
# Docker Run Commands
# ==============================================================================

## docker-operator: Run operator in Docker (update examples/operator1/config first)
docker-operator:
	@printf "$(COLOR_BLUE)Running operator Docker container...$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)Note: Update ./examples/operator1/config/config.yaml first$(COLOR_RESET)\n"
	docker run \
		--name ssv-dkg-operator \
		--rm \
		-p 3030:3030 \
		-v $(CURDIR)/examples:/data \
		$(DOCKER_IMAGE):latest \
		start-operator --configPath /data/operator1/config

## docker-initiator: Run initiator in Docker (update examples/initiator/config first)
docker-initiator:
	@printf "$(COLOR_BLUE)Running initiator Docker container...$(COLOR_RESET)\n"
	@printf "$(COLOR_YELLOW)Note: Update ./examples/initiator/config/init.yaml first$(COLOR_RESET)\n"
	docker run \
		--name ssv-dkg-initiator \
		--rm \
		-v $(CURDIR)/examples:/data \
		$(DOCKER_IMAGE):latest \
		init --configPath /data/initiator/config

# ==============================================================================
# Utility Docker Commands
# ==============================================================================

## docker-build-deposit-verify: Build deposit verification tool
docker-build-deposit-verify:
	@printf "$(COLOR_BLUE)Building deposit-verify image...$(COLOR_RESET)\n"
	DOCKER_BUILDKIT=1 docker build \
		--progress=plain \
		--no-cache \
		-f $(CURDIR)/utils/deposit_verify/Dockerfile \
		-t deposit-verify:latest \
		.

## docker-deposit-verify: Verify deposit data (requires DEPOSIT_FILE_PATH and NETWORK_ENV_PATH)
docker-deposit-verify:
ifndef DEPOSIT_FILE_PATH
	$(error DEPOSIT_FILE_PATH is required. Usage: make docker-deposit-verify DEPOSIT_FILE_PATH=/path/to/deposit.json NETWORK_ENV_PATH=/path/to/.env)
endif
ifndef NETWORK_ENV_PATH
	$(error NETWORK_ENV_PATH is required. Usage: make docker-deposit-verify DEPOSIT_FILE_PATH=/path/to/deposit.json NETWORK_ENV_PATH=/path/to/.env)
endif
	@printf "$(COLOR_BLUE)Verifying deposit data...$(COLOR_RESET)\n"
	cp $(DEPOSIT_FILE_PATH) /tmp/deposit_data.json
	docker run --rm \
		--name dkg-deposit-verify \
		-v /tmp/deposit_data.json:/deposit-verify/utils/deposit_verify/deposit_data.json \
		-v $(NETWORK_ENV_PATH):/deposit-verify/utils/deposit_verify/.env \
		-e DEPOSIT_FILE_PATH=deposit_data.json \
		deposit-verify:latest
	rm -f /tmp/deposit_data.json
	@printf "$(COLOR_GREEN)Verification complete$(COLOR_RESET)\n"
