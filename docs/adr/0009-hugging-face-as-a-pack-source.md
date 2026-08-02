# ADR-0009: Hugging Face as a pack source, compiled in and verified

- Status: accepted
- Date: 2026-08-02
- Deciders: aimd54

## Context

Getting a GGUF was the clumsiest step in using palan. The quickstart offered
a `curl` whose URL the reader assembled by hand, or nine lines of `jq` against
Ollama's blob store, and both ended in a separate `pack`. Neither checked that
what arrived matched what the source published.

The design left one question open on this: an upstream import is "useful on
the internet-facing side, dead weight in the air gap", and asked whether to
ship it behind a build tag.

Two facts, checked against the live API on 2026-08-02:

- `POST /api/models/{repo}/paths-info/main` returns `lfs.oid`, the file's
  upstream SHA-256. palan already had an annotation for exactly that,
  `io.palan.origin.sha256`, defaulted to the weight layer's own digest.
- Hugging Face answers `401` for a repository that does not exist as well as
  for one the caller cannot see, so a refusal cannot be read as "gated".

## Decision

We will accept `hf://<org>/<repo>/<file>` wherever `pack` accepts a path,
rather than adding an import command. Local paths keep working unchanged, so a
fetched model can be packed alongside a template or licence already on disk.

The client will be **compiled in, not hidden behind a build tag**. It is
`net/http` and `encoding/json`, adding no dependency and no meaningful size,
and palan is already a network client that talks to registries. A build tag
would double the release matrix and create a second binary flavour to support,
in order to remove a code path an air-gapped operator never invokes.

Downloads will be **checked against the digest the repository publishes** and
refused on mismatch, and that digest becomes `io.palan.origin.sha256`.

A split GGUF will bring **every sibling part**, and a repository licence will
travel with the weights.

## Consequences

- Seeding a registry becomes one command, which is the step every new user
  meets first.
- Provenance stops being self-referential. For a raw GGUF the upstream digest
  equals the weight layer digest, so the recorded *value* is unchanged; what
  changed is that it was verified against the source rather than derived from
  whatever arrived. A truncated or substituted download now fails before it
  can be packed and signed as genuine.
- Naming one part of a split model can no longer produce an artifact that
  looks complete and fails to load, which is the failure shape this project
  keeps finding.
- palan now depends on a third party's API shape. It is confined to
  `internal/hf` and covered by tests against a local server, so a change
  upstream breaks one package rather than the pack path. The live API is
  exercised only behind `PALAN_E2E_HF=1`, which keeps CI independent of
  Hugging Face's availability and rate limits.
- A refusal cannot distinguish a missing repository from a gated one, because
  the API deliberately does not. The message says so rather than guessing,
  which is the honest reading of a `401` here.
- Not adopted: fetching by revision or from a branch other than `main`, and
  `hf://` as a source for `pull` or `serve`. This is a packing-time import,
  and models enter the system through a registry once packed. Revisit if
  someone needs to pin a repository revision rather than a file.
