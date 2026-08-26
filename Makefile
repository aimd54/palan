# Copyright The palan Authors
# SPDX-License-Identifier: Apache-2.0

SHELL := /usr/bin/env bash

BINARY  ?= palan
MODULE  := github.com/aimd54/palan
VERSION ?= $(shell git describe --tags --always --dirty 2>/dev/null || echo dev)
COMMIT  ?= $(shell git rev-parse --short HEAD 2>/dev/null || echo none)
DATE    ?= $(shell date -u +%Y-%m-%dT%H:%M:%SZ)

LDFLAGS := -s -w \
	-X $(MODULE)/internal/version.version=$(VERSION) \
	-X $(MODULE)/internal/version.commit=$(COMMIT) \
	-X $(MODULE)/internal/version.date=$(DATE)

.PHONY: all
all: build

.PHONY: build
build: ## Build the palan binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/palan

.PHONY: install
install: ## Install palan into GOBIN
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/palan

.PHONY: fmt
fmt: ## Format Go sources in place
	gofmt -w .

.PHONY: fmt-check
fmt-check: ## Fail if any file needs gofmt
	@out=$$(gofmt -l .); if [ -n "$$out" ]; then echo "gofmt needed on:"; echo "$$out"; exit 1; fi

.PHONY: vet
vet: ## Run go vet
	go vet ./...

.PHONY: lint
lint: ## Run golangci-lint
	golangci-lint run

.PHONY: test
test: ## Run unit tests with the race detector
	go test -race -timeout 10m ./...

.PHONY: e2e
e2e: ## Run end-to-end tests (requires Docker; see test/e2e)
	go test -race -timeout 30m -tags e2e -count 1 ./test/e2e/...

.PHONY: tidy
tidy: ## Tidy go.mod/go.sum
	go mod tidy

.PHONY: tidy-check
tidy-check: ## Fail if go.mod/go.sum are not tidy
	go mod tidy -diff

.PHONY: notice
notice: ## Regenerate NOTICE from the modules linked into the released binaries
	go run ./hack/gennotice

.PHONY: notice-check
notice-check: ## Fail if NOTICE no longer matches the module graph
	go run ./hack/gennotice -check

.PHONY: check
check: fmt-check vet lint lint-docs-available tidy-check notice-check test ## All local gates (run before every commit; mirrored in CI)

.PHONY: docs
docs: ## Regenerate the CLI reference under docs/reference
	go run ./hack/gendocs

.PHONY: demo
demo: build ## Re-record docs/assets/demo.gif (requires vhs, ttyd, ffmpeg, gifsicle)
	PATH="$(CURDIR)/bin:$$PATH" vhs docs/assets/demo.tape
	gifsicle --batch -O3 --lossy=80 docs/assets/demo.gif
	@size=$$(wc -c < docs/assets/demo.gif); \
	  printf 'docs/assets/demo.gif: %s bytes\n' "$$size"; \
	  if [ "$$size" -gt 1048576 ]; then \
	    printf 'warning: over the 1 MiB budget for a tracked asset; shorten the\n' >&2; \
	    printf 'tape or lower the framerate rather than committing it as is.\n' >&2; \
	  fi

.PHONY: lint-docs
lint-docs: ## Lint markdown files (requires Node; config in .markdownlint-cli2.yaml)
	npx --yes markdownlint-cli2 "**/*.md"

# What `check` runs, so that a tree with no Node toolchain still has a
# working `make check` on an otherwise pure Go project. The notice is loud
# on purpose: the Docs workflow lints markdown on every pull request
# whatever happens here, so a machine that cannot run it is putting the
# check off rather than avoiding it, and a green `check` that CI then
# fails is the outcome this target exists to prevent.
.PHONY: lint-docs-available
lint-docs-available:
	@if command -v npx >/dev/null 2>&1; then \
	  $(MAKE) --no-print-directory lint-docs; \
	else \
	  echo "NOTICE: npx not found, so markdown was not linted here."; \
	  echo "        CI lints it on every pull request; install Node to see it first."; \
	fi

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin dist coverage.out coverage.html

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "%-12s %s\n", $$1, $$2}'
