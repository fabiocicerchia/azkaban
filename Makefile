# azkaban — minimal, auditable bwrap + landlock sandbox for AI CLIs.
#
# Every verb this repo exposes lives here; `make` on its own prints them,
# grouped, straight out of the `##` comments below.

BIN     := azkaban
VERSION := $(shell git describe --tags --always --dirty 2>/dev/null || cat version.txt)
GO      ?= go

# CGO off everywhere: the binary must be static, and the jail tests must build
# the same way CI and users do. (-race needs cgo, hence no race target.)
export CGO_ENABLED = 0

.DEFAULT_GOAL := help
# help is pure output; the recipe echo would only be noise.
.SILENT: help

##@ General

.PHONY: help
help: ## Show this help
	awk 'BEGIN {FS = ":.*## "} \
	  /^##@/ { printf "\n\033[1m%s\033[0m\n", substr($$0, 5) } \
	  /^[a-zA-Z_0-9-]+:.*## / { printf "  \033[36m%-12s\033[0m %s\n", $$1, $$2 }' \
	  $(MAKEFILE_LIST)

.PHONY: setup
setup: ## Install the pre-commit hook
	@command -v pre-commit >/dev/null 2>&1 && pre-commit install || true

.PHONY: version
version: ## Print the version make would stamp
	@echo $(VERSION)

##@ Build

.PHONY: deps
deps: ## Download and verify module dependencies
	$(GO) mod download
	$(GO) mod verify

.PHONY: build
build: ## Build the jail (static / CGO-free)
	$(GO) build -ldflags '-s -w' -o $(BIN) .

.PHONY: install
install: ## Install the jail into GOBIN (~/go/bin by default)
	$(GO) install -ldflags '-s -w' .

.PHONY: run
run: ## Run the jail (pass args with ARGS="...")
	$(GO) run . $(ARGS)

.PHONY: clean
clean: ## Remove build output and coverage artifacts
	$(GO) clean
	rm -f $(BIN) coverage.out

##@ Quality

.PHONY: lint
lint: ## Run all pre-commit checks on the whole tree
	pre-commit run --all-files

.PHONY: fmt
fmt: ## Format
	$(GO) fmt ./...

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	$(GO) mod tidy

.PHONY: audit
audit: ## Threat-sweep this tree with audit.sh
	./audit.sh .

##@ Tests

# -count=1 everywhere: these tests probe the live kernel (landlock, namespaces,
# mounts), so a pass cached against unchanged sources proves nothing.
.PHONY: test
test: ## Run the test suite
	$(GO) test -count=1 ./...

.PHONY: test-docker
test-docker: ## Also run the docker-socket integration tests (needs a daemon + alpine)
	AZKABAN_DOCKER_IT=1 $(GO) test -count=1 ./...

.PHONY: cover
cover: ## Run tests and write a coverage profile to coverage.out
	$(GO) test -count=1 -coverprofile=coverage.out ./...
	$(GO) tool cover -func=coverage.out | tail -1
