# ADR-0010: Signatures are indexed as referrers as well as tagged

- Status: accepted
- Date: 2026-08-03
- Deciders: aimd54

## Context

[ADR-0007](0007-signature-storage-and-verification.md) settled on cosign's tag
convention as the only storage form for signatures, and set a condition for
revisiting: referrers-API storage was to be reconsidered *"as an addition
alongside the tag, never a replacement, if the ecosystem moves to reading
referrers by default."*

**That condition is not met.** Measured against cosign v2.6.3 on 2026-08-03:

- `cosign sign --registry-referrers-mode` accepts `legacy` and `oci-1-1`, and
  defaults to `legacy`. Selecting `oci-1-1` additionally requires
  `COSIGN_EXPERIMENTAL=1`.
- `cosign verify --experimental-oci11` defaults to false.

Writing and reading referrers are two separate opt-ins. The tag scheme remains
what cosign does unless told otherwise.

Two findings recorded in ADR-0007 stand independently of what cosign defaults
to, and both are defects rather than missing conveniences:

- A registry's referrers API answers nothing for a signed model. ADR-0007 listed
  this among the problems found while exercising the air-gap path, and it stayed
  unfixed. A signature reachable only by constructing `sha256-<digest>.sig` can
  be found by a tool that knows the convention and by nothing else, so a zot UI,
  an `oras discover`, or any policy engine walking referrers sees an unsigned
  artifact.
- A model signed with `cosign sign --registry-referrers-mode=oci-1-1` could not
  be verified at all. That signature carries no tag, so resolving one found
  nothing and the model was reported unsigned. A verifier answering "unsigned"
  for a signed artifact is wrong, not merely incomplete, and the mode is
  reachable by anyone who sets one environment variable.

## Decision

We will attach the signed artifact as the **subject** of the signature manifest
and type that manifest `application/vnd.dev.cosign.artifact.sig.v1+json`, which
is the artifact type cosign uses for the same purpose. Registries index the
signature as a referrer as a result.

**The tag remains, unchanged and authoritative.** It is what `cosign verify
--key` reads, it works on every registry, and the interop suite continues to
enforce both directions on every commit. The subject is an addition, which is
the only form ADR-0007 left open.

Verification will try the tag first and consult referrers only when nothing is
tagged. A signature found either way is held to the same standard: the same
key, the same bound manifest digest, and the same repository identity.

Discovery goes through the transfer library's referrers helper, which uses the
referrers API where the target offers one and walks predecessors otherwise, so a
registry, the local store, and an offline bundle are served by one code path.
That preserves the source-agnostic verification ADR-0007 established.

## Consequences

- A signed model is visible to referrers-based tooling, and a signature written
  by an OCI 1.1 signing tool verifies here. Neither was true before.
- Nothing is required of the registry. The transfer library maintains the
  referrers tag-schema index itself when a registry has no referrers API, so
  registries predating OCI 1.1 keep working without a capability check.
- The signature manifest's own digest changed, since it carries two more
  fields. Nothing addresses a signature by that digest: the tag is derived from
  the *subject's* digest and is unaffected.
- **A subject is a successor.** The signature's tag therefore keeps the model
  manifest and every weight layer reachable, and removing a model without its
  signature left the entire model on disk while `gc` reported success. Garbage
  collection now unlinks referrers whose subject is no longer a tagged artifact,
  which also covers the case `rm` never could: a signature imported without its
  model.
- Deleting such an orphan is not optional. An untagged referrer whose subject
  lies outside the reachable graph sends oras-go v2.6.2's index reload into an
  endless loop, so leaving one behind hangs garbage collection instead of
  failing it.
- The tag is now the fallback in one direction and the primary in the other:
  palan writes both and reads the tag first. Should cosign make referrers its
  default, the ordering in verification is the only thing that would need
  revisiting, and dropping the tag would still be a compatibility break rather
  than a tidy-up.
