# ADR-0007: Signatures travel as cosign tags and verify from any source

- Status: accepted
- Date: 2026-08-02
- Deciders: aimd54

## Context

Two goals in [`architecture.md`](../architecture.md) meet here: models and
runtimes must move through an air gap, and they must be signed and verifiable.
Taken together those imply that a signature can be checked without a network,
which was not true of the implementation.

Findings, measured 2026-08-01 while exercising the air-gap path against a real
registry and an offline host:

- `signing.Verify` took a `*remote.Repository`, so a signature could only be
  checked against a registry. Verifying an artifact carried across a gap in a
  transfer bundle failed with `network is unreachable`, a network error rather
  than a signature verdict.
- `palan save REF` exported only the reference named. The signature lived under
  a second tag, `sha256-<manifest digest>.sig`, and stayed behind unless the
  operator knew to name it as well.
- `palan cp` mirrored a model without its signature, so a model placed in an
  offline registry had to be signed again under the destination name.
- A registry's referrers API reports nothing for a signed model. palan writes
  cosign's tag convention, and nothing was ever written as a referrer, so tools
  looking there find no signature.
- `verify.required` was honoured only by `pull`. The offline sequence of `load`
  then `run` checked nothing at all, so the setting promised an enforcement it
  did not deliver away from a network.

The documentation described the opposite of all of this and was corrected
first, which made the project honest without making it capable.

## Decision

We will keep **cosign's tag convention as the only storage form** for
signatures: `sha256-<manifest digest>.sig` in the model's own repository. Being
readable by `cosign verify --key`, and able to read what `cosign sign` writes,
is a contract the interop suite enforces in both directions on every commit.

Verification will read from **any `oras.ReadOnlyTarget`**, an interface that a
remote repository and an on-disk OCI layout both satisfy, so a registry and a
transfer bundle are interchangeable as sources. The local store is preferred
only when it holds the signature itself: signing follows a push, so a model
packed locally and signed afterwards has its signature on the registry alone,
and treating the local copy as authoritative would report a signed artifact as
unsigned.

Signatures will **travel with the model** on every transfer path, namely
`pull`, `save`, and `cp`, without being named separately. `load` will enforce
the verification policy against the bundle before any content reaches the
store.

Verification will **never excuse content on the strength of its name**. A
reference shaped like a signature must be proven to belong to a model that
verified, or the import is refused.

## Consequences

- A bundle verifies on a host with no network, no transparency log, and no
  certificate authority. The air-gap and signing goals hold together rather
  than only separately.
- The store now holds entries that are not models. They are hidden from `ls`,
  and `rm` unlinks a model's signature so `gc` can reclaim it instead of
  leaving it pinned.
- Signature identity stays bound to the reference it was made for, **registry
  host included**, which is cosign semantics and what stops a signature
  validating another repository's artifact. Measured between two registries on
  2026-08-02: a model copied to a different host fails on identity even when
  the repository path is identical. An offline site must therefore answer on
  the same name the model was signed as, which in practice means the same DNS
  name resolved differently inside the gap. `cp` carries the signature across
  but cannot change what it binds, so a mirror that lands under a different
  host or repository has to be signed again where it lands.
- Because a name proves nothing, the import check runs in two passes and a
  bundle carrying a stray signature-shaped reference is refused whole rather
  than partly imported. An earlier single-pass form skipped such references and
  imported them unverified.
- **Not adopted: referrers-API storage.** Writing signatures as referrers would
  let `oras.ExtendedCopy` carry them without explicit handling, which is
  tidier than copying a second tag on three code paths. It is not what
  `cosign verify --key` reads today, and interop in both directions matters
  more than tidiness. Revisit as an addition alongside the tag, never a
  replacement, if the ecosystem moves to reading referrers by default.
- `run` and `serve` still do not enforce `verify.required`. Content is checked
  as it enters the store, not as it is served. Revisit if the threat model
  comes to include a store modified after import, which would also argue for
  re-checking digests at load time.
