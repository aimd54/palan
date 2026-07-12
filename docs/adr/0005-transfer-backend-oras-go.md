# ADR-0005: oras-go v2 as transfer backend; modctl as interop oracle

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

The design doc (§4, §8.3) preferred delegating the transfer/pack layer to
**modctl** (the ModelPack reference implementation) *if* its logic proved
importable, with oras-go v2 as fallback — "for a solo maintainer,
upstreaming beats reimplementing."

Findings, checked 2026-07-12 against modctl v0.2.2:

- modctl **does** ship an importable `pkg/` tree alongside `internal/`, with
  GoDoc published — the library path exists in principle.
- The project positions itself CLI-first; the README documents commands, not
  a programmatic API. It is pre-1.0 with 43 releases and an actively churning
  API surface.
- moci's M1 acceptance criterion requires the local store to be a **plain
  OCI image layout readable by any OCI tool** ("`oras` can read the store's
  layout", design doc §8.2/§14). modctl manages its own storage layout;
  building moci's store on modctl's stack would couple that guarantee to a
  fast-moving dependency's internals.
- The ModelPack manifest/config construction moci needs is small and
  spec-pinned (media types, fixed layer ordering, canonical config JSON) —
  low-risk to implement directly, and its correctness is *externally
  checkable* against modctl.

## Decision

We will build the transfer and pack layers directly on **oras-go v2**
(`oras.Copy` between `remote.Repository` and `oci.Store`), with ModelPack
types implemented in-repo (`pkg/modelspec`, `internal/pack`). **modctl is a
test dependency, not a runtime dependency**: the CI interop suite must prove
that artifacts packed by moci pull intact with `modctl` and `oras`, and vice
versa.

## Consequences

- The local store stays a standard OCI image layout under moci's control;
  the M1 acceptance criterion is structurally guaranteed rather than
  inherited.
- moci owns ~hundreds of lines of ModelPack packing code that modctl also
  implements; the interop tests are the drift alarm (they double as canaries
  for ModelPack spec evolution, §15).
- Revisit at M2 (design doc §16.6): if the GGUF/raw-layer packing path is
  welcome upstream, contribute it to modctl and shrink moci's pack layer to
  glue; if modctl publishes a stable library API post-1.0, re-evaluate
  delegating transfer wholesale.
