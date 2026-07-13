# Copyright The moci Authors
# SPDX-License-Identifier: Apache-2.0

SHELL := /usr/bin/env bash

BINARY  ?= moci
MODULE  := github.com/aimd54/moci
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
build: ## Build the moci binary into bin/
	CGO_ENABLED=0 go build -trimpath -ldflags '$(LDFLAGS)' -o bin/$(BINARY) ./cmd/moci

.PHONY: install
install: ## Install moci into GOBIN
	CGO_ENABLED=0 go install -trimpath -ldflags '$(LDFLAGS)' ./cmd/moci

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

.PHONY: check
check: fmt-check vet lint tidy-check test ## All local gates (run before every commit; mirrored in CI)

.PHONY: docs
docs: ## Regenerate the CLI reference under docs/reference
	go run ./hack/gendocs

.PHONY: lint-docs
lint-docs: ## Lint markdown files (requires Node; config in .markdownlint-cli2.yaml)
	npx --yes markdownlint-cli2 "**/*.md"

.PHONY: clean
clean: ## Remove build artifacts
	rm -rf bin dist coverage.out coverage.html

.PHONY: help
help: ## Show this help
	@grep -hE '^[a-zA-Z_-]+:.*## ' $(MAKEFILE_LIST) | awk 'BEGIN{FS=":.*## "}{printf "%-12s %s\n", $$1, $$2}'
