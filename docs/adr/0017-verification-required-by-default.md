# ADR-0017: Verification is required by default, and local trust is by digest

- Status: proposed
- Date: 2026-09-28
- Deciders: aimd54

## Context

Every milestone since M8 built out one property: that the bytes a host
serves are the bytes a trusted party vouched for. The checks that make up
that property are in place, and the one the others hang from, the signature
check, is off unless asked for.

- `verify.required` defaults to false. With it set, or with `--verify`, it
  gates `pull` before anything downloads and every model `load` brings in
  ([ADR-0007](0007-signature-storage-and-verification.md)), `run` and
  `serve` at the moment a model is loaded
  ([ADR-0008](0008-verification-at-load-time.md)), and `runtime pull` and
  the engine `run` and `serve` start
  ([ADR-0016](0016-a-verification-result-is-a-chain.md)). Without it, none
  of those checks run, and nothing says so. What runs regardless is
  narrower: blobs are held to their digests as they are copied, which
  proves the bytes match a manifest and says nothing about who wrote the
  manifest. The comparison between the copy a host holds and the artifact
  that verified runs only where a signature was checked, so it is off too.
- Trust comes from `verify.key` or `verify.policy`. With neither set, a
  verification fails with "no verification key configured".
- `palan sign` signs a model on its registry. A model packed locally and
  never pushed cannot be signed, so under a required policy it could never
  be run. A store filled before signing existed is in the same position, and
  so is anything whose publisher does not sign.
- The policy is the `verify:` section of the config file. The config
  reader ignores keys it does not know, at the top of the section and
  inside policy and source rules alike. A misspelt `verify.rehsh: true` is
  a host that never re-reads its weights, and a policy rule that misspells
  `identites:` trusts its keys alone. Nothing records which version of the
  format a file was written for.
- Every key can also be set from the environment, as
  `PALAN_VERIFY_REQUIRED` and so on, so what a process enforces is not
  always what its config file says.
- [ADR-0016](0016-a-verification-result-is-a-chain.md) deferred to 1.0
  whether re-reading the weights should become the default alongside
  verification, and left an engine taken from `PATH` reported rather than
  refused.

A 1.0 is a statement about defaults as much as about features. Shipping it
with the property off means the host that most needs it, one set up once
and left alone, is the one least likely to have it. The roadmap also
commits 1.0 to a first-run path that does not strand a store predating
signing.

## Decision

We will make **`verify.required` true by default**. `pull`, `load`,
`runtime pull`, `run` and `serve` verify unless `verify.required` is set to
false, in the config or in the environment. `--verify` keeps its meaning,
forcing a check where `verify.required` is false, and nothing is added to
skip one from the command line.

- A host with no key, no policy and nothing trusted is refused, and the
  refusal names every way forward: a key, a policy, a trusted digest, or
  turning verification off. Where the refused content resolved to a digest,
  the refusal prints it with the command that trusts it.
- When verification is off, it says so. Every command that would have
  checked prints one line on stderr naming where the setting came from, the
  config file or the environment, and `--json` output carries the same
  fact. Silence would read the same as a check that passed, which is the
  reasoning ADR-0016 applied to an engine taken from `PATH`.
- Re-reading the weights stays opt-in, under `--rehash` and
  `verify.rehash`. Nothing has measured its cost on the hardware models are
  served from, and the comparison between the resident copy and the
  artifact that verified, which costs nothing, becomes a default with the
  signature check it depends on.
- An engine taken from `PATH` stays reported rather than refused. Refusing
  it would strand every host serving with a distribution package, and a
  runtime artifact is already held to the same gate as a model.

We will let an operator **trust an artifact by its digest**. `palan trust
add` records a manifest digest, and a trusted digest satisfies verification
wherever that content is loaded, under any name. This is how a locally
packed model, a store that predates signing, or content whose publisher
does not sign is admitted one artifact at a time without switching
verification off.

- `trust add` takes `REF@sha256:…` or a bare `sha256:…` digest and records
  it as given, with nothing looked up. A tag is looked up in the local store
  and nowhere else. Looked up on a registry, `trust add REF && pull REF`
  would admit whatever the tag pointed to without anyone having held a
  digest, which is verification switched off one name at a time.
- `pull` and `load` refuse before content reaches the store, so the digest
  form is the only way to admit what they refuse, and their refusal prints
  the digest of each artifact it refused. That digest is the arriving
  content's own: trusting it pins exactly those bytes and says nothing about
  whether they are good. An operator holding a digest from elsewhere, a
  publisher's release notes or the host that packed the model, compares the
  two.
- `trust add` takes several references at once, and `--all-in-store`
  trusts every model and runtime the store holds, printing each digest.
  That is the first-run path for a store that predates signing: one
  deliberate command that admits exactly what is there now and nothing
  that arrives later.
- Trusted digests live in `trust.yaml` beside the config file in use, or
  wherever `verify.trust-file` points. One file and one format means there
  is no precedence to settle between two sources. Where the file is
  mounted read-only, as from a Kubernetes ConfigMap, `trust add` fails and
  names it, and the entries are written into the ConfigMap instead.
- The file has exactly the protection of the config, and that is enough:
  whoever can write the config can already set `verify.required: false`.
  What trust must not share is the store. A store is copied, carried on
  removable media and filled from bundles, and trust kept there would
  travel with the content it vouches for.
- The file is read again on every check, as the signature is
  ([ADR-0008](0008-verification-at-load-time.md)), so removing an entry
  takes effect on the next load without restarting `serve`.
- Each entry records the digest, the name it was added under, when, and an
  optional note. `trust ls` lists them and `trust rm` removes one. `rm` and
  `gc` leave entries alone: an entry describes content rather than a store
  entry, so the same bytes pulled again are trusted again.
- A trusted digest decides on its own, under any name, including names a
  policy rule restricts to particular signers. A digest pins content, and
  names are not what verification protects, so an operator's recorded
  decision ranks above the standing policy, as `--key` already does.
  Signatures are not consulted to reach that verdict, so one attached later
  cannot withdraw it: anyone who can push to a repository can attach a
  signature ([ADR-0015](0015-keyless-verification-from-carried-material.md)),
  and letting a bad one refuse trusted content would hand them a way to
  stop it being served.
- `trust add` refuses an artifact whose signatures contradict it: one that
  names a different digest, or a keyless signature that does not verify
  under its own certificate. Trusting it would hide the one piece of
  evidence that something was substituted. A signature that simply does not
  verify under the keys configured here is not such evidence, since it may
  be a publisher's key this host was never given, so the artifact is added
  with a note naming what was found. With no key or policy configured it is
  added with a note that no signature was checked, and one that would
  verify anyway is added with a note that trust was not needed. These
  checks read what the store holds, so a digest recorded ahead of a `pull`
  or `load` has nothing to read yet, and its entry says so.
- A result satisfied by a trusted digest says so. `verify`, `--explain`
  and the lines `pull`, `load`, `runtime pull`, `run` and `serve` print
  report "trusted locally", never "verified", and `--json` gives it a
  verdict value of its own
  ([ADR-0011](0011-terminal-output-is-decoration.md)). `verify` exits 0 for
  it, because the host will load it and the exit status answers that
  question. `--explain` shows the entry, when and under what name it was
  added, and what any signatures say, so content that has since been signed
  shows that its entry can be removed.
- `ls` and `describe` do not report it. Listing does not verify
  (ADR-0008), and a marker on trusted content alone would make every other
  entry's blank read as unverified.
- `pack` is not gated by `verify.required`, since it creates the artifact,
  though it still checks a publisher's signature when given a key
  ([ADR-0013](0013-publisher-signatures-at-import.md)). Where verification
  is required and the result is not trusted, it says that the result needs
  a signature or `trust add` before `run` will accept it.
- `serve` answers a refused load with the same ways forward as the command
  line, in the body of its `403`. `/v1/models` lists what the store holds
  without verifying it (ADR-0008), and on a fresh install that is
  everything it will refuse.

We will make **the `verify:` section a stable, versioned format**. Its keys
and their meaning are stable until 2.0, and `trust.yaml` is held to the
same promise under a `version` of its own.

- `verify.version` names the format, and absent means 1. It changes only
  when a meaning changes, which is what 2.0 is for, and a version this
  binary does not know is refused, naming it.
- A key added during 1.x does not change the version. An older 1.x binary
  refuses it as unknown, and the refusal says that the config may have been
  written for a newer palan.
- An unknown key anywhere under `verify:`, inside policy rules, their
  identities and source rules included, is refused when the config is read,
  so a typo is an error rather than a policy that quietly does nothing.

## Consequences

- A fresh install cannot run an unsigned model until its operator decides
  how it is to be trusted. That is the point of the change, and the refusal
  is written to be the documentation for it.
- Upgrading a store that holds unsigned content stops `run` and `serve` on
  that content. The refusal lists the references and the command that
  admits them; `trust add --all-in-store` admits all of them at once, and
  `verify.required: false` restores the old behaviour.
- Scripts that pull unsigned models, the quickstart, the guides, the e2e
  suite and the Kubernetes examples need a key, a trusted digest, or an
  explicit `verify.required: false`. `deploy/k8s-examples/init-puller.yaml`
  configures no verification at all and is refused under the default.
- Trusting by digest adds a third kind of trust beside keys and keyless
  identities. It is local by construction: nothing about it travels with
  the artifact, so a bundle carried to another host has to be trusted, by
  the digests its refusal prints, or signed there as well.
- A trusted digest stays trusted when a signature later appears,
  disappears or fails. Retiring it is `trust rm`, and `--explain` shows
  when an entry has become unnecessary.
- A host running with verification off says so on every command that would
  have checked. That is noise on a laboratory machine and the point
  everywhere else.
- Refusing unknown keys under `verify:` can break a config that carried a
  misspelt or retired key, and a config written for a later 1.x is refused
  by an earlier binary. Both are the intended failure; other sections keep
  their current tolerance.
- A host on shared or removable storage still has to ask for the weights
  to be re-read. Revisit that default once its cost has been measured on
  the hardware models are served from.
- Revisit the digest-trust store if palan gains multi-user stores, where
  one user's trust decision should not become another's.
