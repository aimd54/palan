# Contributing to palan

Thank you for your interest in contributing! The conventions below keep
the project easy to review, audit, and maintain.

## Developer Certificate of Origin (DCO)

All commits must be signed off, certifying the
[Developer Certificate of Origin](https://developercertificate.org/):

```sh
git commit -s
```

This appends a `Signed-off-by: Your Name <you@example.com>` trailer matching
your git identity. Unsigned commits cannot be merged.

## Commit messages

We use [Conventional Commits](https://www.conventionalcommits.org/en/v1.0.0/):

```text
<type>(<optional scope>): <imperative subject>

<body: what and why, wrapped at ~72 columns>
```

Common types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`.
Scopes mirror the package tree, e.g. `feat(store): ...`, `fix(router): ...`.
Keep commits small and self-contained; every commit must build and pass tests.

## Development setup

Requirements: Go ≥ 1.26, `make`, [golangci-lint](https://golangci-lint.run/) v2,
and Docker (end-to-end tests only). If golangci-lint panics with a Go version
mismatch, rebuild it against your toolchain:
`go install github.com/golangci/golangci-lint/v2/cmd/golangci-lint@v2.12.2`.

```sh
make build      # build bin/palan
make check      # gofmt, go vet, golangci-lint, tidy check, race-enabled unit tests
make e2e        # end-to-end tests against a local zot registry (requires Docker)
make lint-docs  # markdownlint over the docs (requires Node)
make help       # list all targets
```

Run `make check` before every commit; CI runs the same gates.

## Testing policy

New functionality comes with new tests, and bug fixes come with a test that
fails before the fix and passes after it. A pull request that adds behaviour
without covering it will be asked for tests before review continues.

What that means in practice:

- Unit tests next to the code, in the same package for unexported behaviour.
- Parsers that read untrusted input (GGUF headers, references, annotations,
  archives) get a `Fuzz*` target alongside the table tests.
- Changes to transfer, packing, or signing get an end-to-end case in the
  `make e2e` suite, which runs against a real registry and the interop tools.
- Write the assertion so it fails when the feature is broken. Checking that a
  command exits 0 rarely does: much of what this project talks to reports
  success while doing nothing, so assert the state you expect to see.

## Code conventions

- Go code is formatted with `gofmt` and `goimports`
  (local prefix `github.com/aimd54/palan`).
- Every source file starts with the SPDX header:

  ```go
  // Copyright The palan Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- Exported packages live under `pkg/`, implementation under `internal/`.
- Architectural decisions are recorded as ADRs in [`docs/adr/`](docs/adr/);
  significant design changes should come with a new ADR, not an edit to
  history.

## Filing issues and pull requests

- Use the issue templates for bugs and feature requests.
- PRs should reference the issue they address and describe testing performed.
- Interoperability is a contract: artifacts packed by palan must remain
  pullable by `oras` and `modctl` (see the interop test suite). Changes that
  break this will not be accepted.
