# Contributing to moci

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

```
<type>(<optional scope>): <imperative subject>

<body: what and why, wrapped at ~72 columns>
```

Common types: `feat`, `fix`, `docs`, `test`, `ci`, `chore`, `refactor`.
Scopes mirror the package tree, e.g. `feat(store): …`, `fix(router): …`.
Keep commits small and self-contained; every commit must build and pass tests.

## Development setup

Requirements: Go ≥ 1.24, `make`, [golangci-lint](https://golangci-lint.run/) v2,
and Docker (end-to-end tests only).

```sh
make build      # build bin/moci
make check      # gofmt, go vet, golangci-lint, tidy check, race-enabled unit tests
make e2e        # end-to-end tests against a local zot registry (requires Docker)
make help       # list all targets
```

Run `make check` before every commit — CI runs the same gates.

## Code conventions

- Go code is formatted with `gofmt` and `goimports`
  (local prefix `github.com/aimd54/moci`).
- Every source file starts with the SPDX header:

  ```go
  // Copyright The moci Authors
  // SPDX-License-Identifier: Apache-2.0
  ```

- Exported packages live under `pkg/`, implementation under `internal/`.
- Architectural decisions are recorded as ADRs in [`docs/adr/`](docs/adr/);
  significant design changes should come with a new ADR, not an edit to
  history.

## Filing issues and pull requests

- Use the issue templates for bugs and feature requests.
- PRs should reference the issue they address and describe testing performed.
- Interoperability is a contract: artifacts packed by moci must remain
  pullable by `oras` and `modctl` (see the interop test suite) — changes that
  break this will not be accepted.
