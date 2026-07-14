# ADR-0006: Rename the project from moci to palan

- Status: accepted
- Date: 2026-07-14
- Deciders: aimd54

## Context

The design doc (§16.1) accepted `moci` (model + OCI) as a working codename
but required a rename before public release: the GitHub username `moci` is
taken (no org possible at that path), npm `moci` is an active unrelated CLI,
and several unrelated repos share the name — poor searchability for a
project that hopes to be found.

§16.1 listed three candidates to vet; checked 2026-07-14, plus a wider
slate:

- **gantry** — rejected. Gantry (gantry.io, GitHub org `gantry-ml`) is a
  venture-funded ML observability company: a direct collision in the ML
  tooling space.
- **gollem** — rejected. `m-mizutani/gollem` is an active Go framework for
  agentic LLM apps, adjacent to several Go LLM libraries named `gollm`, and
  one letter from GitHub's `gollum` wiki — same language, same space.
- **capstan** — rejected. `cloudius-systems/capstan` is a known
  "Docker-for-unikernels" packaging tool: container-tooling collision.
- **palan** — clean. No project in the cloud-native, OCI, or ML space uses
  it: the neighbours are a hobby programming language (`tosyama/palan`) and
  a small web agency. npm and Homebrew names are free; `palan.io` and
  `palan.sh` were unregistered at check time. The GitHub username is
  squatted by an empty account — the same situation `moci` was in, and
  irrelevant while the repo lives under a personal namespace.

On meaning: a *palan* is the French block-and-tackle hoist for lifting
heavy loads — a tool whose job is pulling weights, which is literally what
this CLI does. The same word names a pack-saddle in Persian and Turkish,
and shares its root with *palanquin*; the whole word family is about
carrying heavy things.

Timing: the rename must land before the first public tag. The module path
is baked into `go.mod` and every import; renaming after a release would
break the Go module path for anyone importing `pkg/modelspec`.

## Decision

We will rename the project from `moci` to `palan`, wholesale, before
tagging v0.1.0: module path (`github.com/aimd54/palan`), binary and CLI
name, config and state paths (`~/.config/palan`, `~/.local/share/palan`,
`PALAN_HOME`), annotation keys (`io.palan.*`), runtime-artifact media types
(`application/vnd.palan.runtime.*`), Prometheus metric prefix (`palan_`),
release and image names.

Historical records keep the codename: the design document and ADR-0001
through ADR-0005 predate the rename and still read `moci`. They are
immutable records of decisions made under that name, not stale references.

## Consequences

- Nothing to migrate: no release, no users, no published artifacts existed
  under the old name. This is the whole point of renaming pre-tag.
- Readers of the design doc must map `moci` → `palan`; the README points
  here.
- The name is a common noun in French (a literal hardware-store hoist), so
  bare-word French search results are muddy — qualified searches
  ("palan cli", "palan oci") are clean. Same trade-off `helm` lives with.
- Revisit only if a trademark or a significant namesake project surfaces
  before wide release; after v0.1.0 the module path makes renaming
  expensive.
