# ADR-0013: Verify a publisher's own signature when a model is imported

- Status: accepted
- Date: 2026-08-18
- Deciders: aimd54

## Context

[ADR-0007](0007-signature-storage-and-verification.md) and
[ADR-0008](0008-verification-at-load-time.md) cover signatures palan writes
over artifacts palan packed. They say nothing about the stretch before that:
a model arrives from the repository that published it, and until it is packed
and signed locally, the only thing vouching for those bytes is whatever the
publisher released alongside them.

[ADR-0009](0009-hugging-face-as-a-pack-source.md) closed part of this by
checking each downloaded file against the SHA-256 the repository publishes.
That check has a limit worth stating plainly: a repository publishes a digest
only for the files it stores in LFS. Weights and shards are covered;
`config.json`, the tokenizer files and the licence are served inline and
publish no digest at all, so nothing about them is checked. Those files decide
how a model tokenizes and what template it answers under, so an unchecked
tokenizer or chat template is a real gap rather than a cosmetic one.

Model publishers have begun signing what they release. The OpenSSF
model-signing format is the one the publisher side is converging on: NVIDIA
signs the models in its own catalogue with it, and its reference
implementation is the `model_signing` tool. The format is a Sigstore bundle
holding a DSSE envelope whose payload is an in-toto statement.

Facts checked on 2026-08-17 against `model-signing` 1.1.1, since the
documentation and the implementation differ in a way that decides how the
format is read:

- Per-file digests live under the statement's **`predicate.resources`**, as
  name, algorithm and digest triples whose names are paths relative to the
  directory that was signed, spelled with forward slashes. The top level
  `subject` array holds a single entry for the model as a whole, carrying an
  aggregate digest that identifies no individual file. Reading `subject` as
  the per-file listing yields one entry that matches nothing a caller asks
  about.
- The tool writes its signature to `model.sig` by default and excludes that
  file from the resources it lists whenever the signature is written inside
  the directory being signed.
- Its key flags are `--private_key` and `--public_key`.

A signature in this format covers every file the publisher signed, inline
files included, which is exactly the set the published digests miss.

## Decision

We will **verify a publisher's signature at import, in the OpenSSF
model-signing format, against a key the operator supplies**, and refuse
anything that signature does not cover.

- `pack` gains `--oms-key`, naming a PEM public key. Given one, the
  repository's `model.sig` is fetched and verified before any weight bytes are
  packed, and every downloaded file is held against what the signature covers.
  A file the statement omits, and a file whose bytes on disk hash to something
  else, each refuse the import.
- The digest compared is computed from the bytes that landed on disk, never
  the digest the repository's API advertised. Comparing the API against itself
  would prove nothing about the content.
- Per-file digests are read from `predicate.resources`. The aggregate
  `subject` entry is not decoded at all, so it cannot be mistaken for a file.
- Verification is **key based**. A keyless signature carries its trust
  material in the same bundle and needs a trusted root to check it against,
  which is a separate decision with its own offline story.
- A key supplied against a repository that publishes no signature is
  **refused**, not quietly downgraded to an unverified import. The request was
  to verify.
- A key supplied alongside a local path is refused as well. A local file
  carries no publisher signature, so honouring the key for part of an artifact
  would leave the rest of it vouched for by nothing.
- The key that verified is recorded on the manifest as
  `io.palan.origin.signer`, derived from the verifier's own public key rather
  than from anything inside the bundle.
- Signatures palan itself writes are unchanged. cosign remains the only form
  for those, per ADR-0007, and the two live at different layers: a publisher
  signs files, palan signs an OCI manifest.

## Consequences

- What enters the store from a repository can be checked against the
  publisher's own attestation rather than only against digests the same API
  served. The inline files that publish no digest are covered here for the
  first time.
- The project now reads a signature format it does not write, from a different
  ecosystem than the one it signs with. The two are kept apart deliberately:
  `internal/omsig` verifies and never signs, and nothing in the packing path
  translates one form into the other.
- Correctness now depends on an upstream format detail that the specification
  text alone does not settle. An interoperability test signs a directory with
  the real tool and verifies the result, in the shape the oras, modctl and
  cosign round-trips already take, and it pins the relative spelling of a
  nested resource name because the import path compares those names exactly.
  A release that changed the spelling would refuse imports rather than accept
  wrong ones, and the test is what would say so.
- An operator without a key sees no change. Digests are still checked where
  they are published, and nothing claims a signature was verified when none
  was.
- Provenance and enforcement stay separate concerns: this decides what may
  enter the store, while [ADR-0008](0008-verification-at-load-time.md) still
  decides what may be served.
- Revisit when a trusted root can be carried and pinned for offline use, which
  is what keyless verification waits on, and again if the format grows a
  binding that lets a publisher's signature travel as an OCI referrer, which
  would let it move with the artifact instead of being fetched from the
  repository it came from.
