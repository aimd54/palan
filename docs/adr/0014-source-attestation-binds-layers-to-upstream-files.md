# ADR-0014: A source attestation binds layers to the upstream files they came from

- Status: accepted
- Date: 2026-08-24
- Deciders: aimd54

## Context

A packed layer already carried `io.palan.origin.sha256`, the digest the
source repository published for the file, checked against the bytes before
packing ([ADR-0009](0009-hugging-face-as-a-pack-source.md)). Two limits made
that a weaker claim than it reads as.

The value is provably equal to the layer's own digest, because a download
whose bytes miss the published digest is refused. So what the annotation
really asserts is the boolean "some publisher released these exact bytes
under a matching digest". It names neither the publisher nor the file.

And an annotation is not signed on its own. A signature covers the manifest,
so editing an annotation invalidates it, but nothing states in a portable
form that these layers hold those upstream files. A verifier reading the
artifact on another host has the claim and no way to check it against
anything.

Facts checked while deciding:

- `cosign attest` writes the envelope as a manifest layer of media type
  `application/vnd.dsse.envelope.v1+json`, tagged `sha256-<digest>.att`,
  with exactly two annotations on that layer:
  `dev.cosignproject.cosign/signature`, empty, and `predicateType`. Its
  manifest sets no `subject` and no manifest-level artifact type. Read on
  2026-08-24 from a manifest the tool itself produced against zot, not from
  documentation.
- `cosign verify-attestation` **refuses** an attestation whose envelope
  layer lacks the signature annotation, reporting the layer as missing it,
  whatever the envelope contains. It does not need `predicateType`: with
  that annotation removed and everything else unchanged, a type-filtered
  verification still matched, so cosign reads the predicate type from
  inside the envelope. Both halves measured on 2026-08-24 by removing one
  annotation at a time and running the real binary.
- Hugging Face's `/api/models/{repo}` reports `sha`, the commit the listing
  was resolved at, and `/resolve/<rev>/<path>` accepts that commit in place
  of a branch name. Checked 2026-08-18.

## Decision

We will emit a **signed statement binding each layer's digest to the
upstream file it was fetched from**, written when a model is signed and
checked when it is verified.

**The statement is an in-toto Statement in a DSSE envelope**, predicate type
`https://palan.dev/source/v1`, whose predicate lists one entry per layer:
the layer's own digest, the repository, the path within it, the revision,
and the digest the repository published. The subject is the model manifest's
digest.

**It is stored the way a signature is stored**: an OCI manifest under
cosign's `sha256-<digest>.att` tag, with the model manifest as its `subject`
so registries index it through the referrers API, and with the two
annotations cosign puts on the envelope layer. Both discovery paths work,
as they do for signatures
([ADR-0010](0010-referrers-alongside-the-signature-tag.md)). Only the
signature annotation is load-bearing for cosign; `predicateType` is written
because cosign writes it, so an attestation from either tool has the same
shape for anything reading manifests rather than payloads.

**`pack` records the source facts as layer annotations**,
`io.palan.source.repo`, `io.palan.source.path` and
`io.palan.source.revision`, written only when a value exists. A purely
local pack records none, and its artifact stays byte identical to what it
was before.

**A layer whose source is not fully known contributes nothing to the
statement**, and a statement covering no layers is refused rather than
produced. A statement that verifies while vouching for nothing is worse than
no statement, because it reads as a checked chain.

**`pack` now fetches from the commit the listing resolved to**, rather than
from `main` a second time. That commit is validated as forty hexadecimal
characters at the point it is decoded, because it reaches both a URL path
and a signed annotation.

**The attestation travels with the model** through `pull`, `save` and `cp`,
and each of those reports whether it did.

This adopts one half of what ADR-0009 recorded as not adopted. That entry
covered two things: fetching by revision, and a user-supplied revision as
part of the reference. **The second still stands.** There is no
`hf://org/repo@rev` and no flag to pin one; a reference still names a
repository and a file, and a caller cannot ask for a branch other than the
default. What changed is internal: having resolved a listing, palan fetches
the files from the commit that listing reported instead of asking for a
moving branch again. ADR-0009's reason for the exclusion, that this is a
packing-time import rather than a way to address models, is untouched.

## Consequences

- The chain from a repository's published digests to the blobs in a store is
  checkable on a host with no network, against a registry, a bundle, or a
  store, by anyone holding the public key.
- A time-of-check to time-of-use gap closes. Listing a repository and then
  fetching from `main` could pack files from a commit that was never listed,
  and the recorded revision would have been a claim about a different tree.
- An artifact packed from local files is unchanged, byte for byte. The
  annotations are conditional and the statement is not written when no layer
  carries a source, so nothing about an offline workflow moves.
- palan and cosign read each other's attestations. That is a property held
  by a test that runs the real binary, not by this document: writing to the
  published format produced an attestation cosign refused outright, and only
  the tool revealed it.
- The recorded revision is the one the repository reported at listing time.
  It is not independently verifiable: a source that lies about its own
  commit is recorded faithfully as having said so. What the statement proves
  is that these layers hold the files that repository served under those
  digests, which is a claim about palan's handling, not about the source's
  honesty.
- A layer packed from a source that publishes no digest for a file, which is
  every inline non-LFS file on Hugging Face, is attested with its repository,
  path and revision but no published digest. The statement says what is
  known and omits what is not, rather than implying a check that never
  happened.
- Verification of an artifact that carries no attestation stays a success.
  Requiring one is a policy question, and the policy layer is M10's; until
  it exists, refusing here would break every artifact packed before this
  change.
- Two repositories publishing a same-named file still produce two layers
  sharing one `org.cncf.model.filepath`. The statement distinguishes them by
  digest and by source, so the ambiguity is now visible where it was not,
  but the artifact still carries it.
- Revisit when a source other than Hugging Face is added. The predicate's
  fields are deliberately generic, repository, path, revision and published
  digest, and nothing in them is specific to that API, but only one source
  has exercised them.
