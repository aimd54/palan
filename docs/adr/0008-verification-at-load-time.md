# ADR-0008: Enforce the verification policy when a model is loaded

- Status: accepted
- Date: 2026-08-02
- Deciders: aimd54

## Context

[ADR-0007](0007-signature-storage-and-verification.md) left one condition
open: `run` and `serve` did not enforce `verify.required`, so content was
checked entering the store and never afterwards. It named the threat model
that would change the answer, namely a store modified after import.

Two findings settled it, both verifiable in the tree before this change:

- **`run` bypassed the policy entirely for a model it had to fetch.**
  `ensureModel` called the transfer client's `Pull` directly rather than the
  gate in the `pull` command, so with `verify.required` set an unsigned model
  was downloaded and served. Neither `run.go` nor `serve.go` mentioned
  verification anywhere.
- **Nothing re-read the store.** `pull` and `load` inspect content on its way
  in. Anything writing to the store between import and serving was trusted,
  which makes the guarantee one about transfers rather than about what runs.

The cost of closing this changed with ADR-0007. While verification could only
read a registry, gating a model load meant a network round trip per load,
which is unusable on the air-gapped host the feature exists for. Reading the
local store made it a file read and one signature check.

## Decision

We will check the signature **at the point a reference becomes runnable**,
which is one place per command: `storeBackend.Spec` for `serve`, and before
the decision to fetch in `run`. Both reuse the source selection from
ADR-0007, so the store answers when it holds the signature and the registry
answers otherwise.

`run` will check **before** deciding to pull, so an unsigned model is refused
without being downloaded first.

A model that exists but fails its check is **refused, not missing**. The
router gains an exported sentinel and answers `403`, rather than the `404` it
returns for a reference it cannot resolve.

`/v1/models` will **not** verify. Listing reports what the store holds.

## Consequences

- `verify.required` now covers every way a model gets in or gets used:
  `pull`, `load`, `run`, and `serve`. The guarantee is about what runs, not
  only about what was transferred.
- `serve` checks per load rather than per request, so the cost is paid when a
  model is spawned, not on the hot path. It repeats after an eviction, which
  is intended: the point is to re-read a store that may have changed.
- A refusal is scoped to one model. `serve` keeps running and keeps serving
  everything else, because the check happens at load rather than at startup.
  Nothing preloads, so a bad model cannot stop the process from starting.
- Verification results are not cached. Caching would defeat the re-read that
  motivates this, and the check is a store read plus one signature
  verification over a payload of a few hundred bytes.
- Listing an unverified model that then fails on use is a deliberate
  asymmetry. Verifying every entry per listing would be wasteful and would let
  a single bad artifact break an endpoint that only reports existence.
- Not covered: blob digests are not re-checked at load time. That would catch
  a corrupted or substituted weight file whose manifest still verifies, and it
  is a different guarantee with a different cost, since it means rehashing
  gigabytes rather than validating a signature. Revisit if the threat model
  comes to include an attacker who can write blobs but not manifests.
