# ADR-0015: Keyless signatures are verified from material carried with the artifact

- Status: accepted
- Date: 2026-09-03
- Deciders: aimd54

## Context

palan verifies a signature against a public key held on disk, so
verification needs no network once the signature is in the local store
([ADR-0007](0007-signature-storage-and-verification.md)). A trust policy
names which keys may sign which references, and refuses a reference no rule
covers.

A growing share of published artifacts are signed without a key at all. A
keyless signature names an identity, a person or a workload authenticated by
an OpenID provider, and the signer holds a certificate that lives for about
ten minutes. Verifying one normally reaches two services: a certificate
authority, to establish that the certificate was issued, and a transparency
log, to establish that the signature was recorded while the certificate was
valid. Neither is reachable from a disconnected host, which is the host
palan exists to serve.

Facts checked while deciding:

- cosign 2.6.3 writes two different things for a keyless signature. By
  default it attaches the certificate and a signed entry timestamp as
  annotations on a simple-signing layer. With `--new-bundle-format` it
  writes a Sigstore bundle, version 0.3, attached as a referrer, carrying
  the certificate, the log entry, and an inclusion proof with a checkpoint
  the log signed.
- Only the second carries an inclusion proof. A signed entry timestamp is
  the log's promise that it will record an entry; an inclusion proof is
  evidence that it did, and it can be checked against a log key alone.
- The two prove different things, and neither substitutes for the other. A
  checkpoint signs the log's size and root and carries no date; the entry's
  own bytes carry none either. The signed entry timestamp is the only thing
  in a bundle that dates a signature, because it signs the date together
  with the entry's bytes, the log's identity and the entry's position.
- The bundle and trusted root formats are defined in
  `github.com/sigstore/protobuf-specs`, which palan's dependency graph
  already contained.
- `github.com/sigstore/sigstore-go` implements this verification. Adding it
  brings 54 modules palan does not otherwise have, including a Swagger
  runtime, gRPC, OpenTelemetry and a Kubernetes logging library. palan links
  74 modules in total.
- A keyless signing certificate expires minutes after it is issued, so at
  any realistic moment of verification it is expired.

## Decision

We will verify keyless signatures from material carried with the artifact,
against a Sigstore trusted root the operator pins on disk, and we will not
sign that way.

The bundle is the only accepted form. A signature carrying a signed entry
timestamp and no inclusion proof is refused rather than accepted on weaker
evidence, because the two are not interchangeable and an operator reading
"verified" cannot see which one was checked.

The trusted root is the Sigstore trusted root, the file
`cosign trusted-root create` writes and Sigstore's own update framework
distributes. It is pinned per policy rule rather than once for the whole
configuration, since two registries need not draw on the same Sigstore
instance.

Verification is implemented directly on the protobuf definitions rather than
by adding `sigstore-go`. The checks are the DSSE signature, the log's signed
entry timestamp, the RFC 6962 inclusion proof with its checkpoint signature,
the binding of the proven log entry to the signature in hand, the
certificate chain, the subject and issuer from the certificate, and the
binding from the signed statement to the artifact's digest.

A certificate is checked against the moment the transparency log recorded
the signature, not against the present, since by any later moment it has
expired. That moment is taken from the log's signed entry timestamp and from
nothing else. An entry carrying no such signature is refused rather than
accepted with the date it states: a certificate that may be checked against
a moment its own bundle chose does not expire, so accepting one is the same
as having no expiry check while reporting one.

Every keyless signature attached to an artifact is checked, and every one is
carried. An artifact may legitimately carry several, and anyone who can push
to its repository can attach another, so examining only the first would let
that person decide which signature is examined. For the same reason a bundle
is never discovered by tag: discovery asks what refers to the artifact,
since a tag is something a pusher can create. The name palan gives a bundle
in its own store exists only so that transfer can move it by name, and is
derived from the bundle rather than from what it signs, so two of them do
not collide.

A policy rule names identities as a subject and an issuer. The subject is
matched as a pattern in which `*` stands for any run of characters, because
a workload identity carries the ref that built it and changes with every
release. The issuer is matched exactly. A subject pattern must pin a domain:
in an address and in a URL the domain is the part a signer cannot choose for
themselves, so a pattern without one matches identities belonging to whoever
cares to mint them. A certificate naming its holder more than once is
refused rather than resolved by reading the first name.

Signing keyless is out of scope. Producing such a signature requires the
certificate authority and transparency log this decision exists to avoid
depending on.

## Consequences

An artifact signed by a published workflow can be verified on a host with no
network, which was not possible before: such artifacts were simply
unverifiable by palan.

The dependency graph is unchanged. Two modules move from indirect to direct.

The verification code is palan's own, which means palan carries the cost of
following the formats as they change. The formats are versioned and the
media type is matched by prefix, so a later bundle version is found rather
than overlooked, and the refusal it produces names the version.

Some real signatures are refused: anything signed without
`--new-bundle-format`, anything whose bundle identifies its signer by bare
public key rather than by certificate, and anything whose log entry carries
no signed timestamp. Each refusal names what is missing.

A bundle backed by a log that issues no signed entry timestamp would be
refused for want of a date. Should such a log matter here, the replacement
is an RFC 3161 timestamp over the signature, which the bundle format already
carries a field for, and not trusting the entry's stated date.

Two checks a fuller implementation makes are not made here. The signed
certificate timestamp embedded in the certificate is not verified, so a
certificate authority that issued a certificate without logging it is not
detected; pinning that authority is already an act of trust in it. The
checkpoint's origin line is not compared against the log's name, so one key
serving two trees would satisfy either. Both are recorded rather than left
to be discovered.

A source attestation is verified against the key that signed the model. A
model verified by a keyless signature therefore has its provenance reported
as unchecked rather than checked, which is a gap to close when keyless
attestations are read as well.

This decision should be revisited if the Sigstore bundle gains a version
whose verification differs in kind rather than in detail, or if the checks
listed as not made turn out to matter for a deployment palan is used in.
