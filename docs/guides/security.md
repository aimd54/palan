# Security guide

Model weights are attacker-controlled, code-adjacent inputs: they are
mmapped by native code and their templates steer your agents. palan treats
their distribution accordingly. See also the [security
model](../architecture.md#security-model) overview.

## What you get by default

- **Digest verification everywhere**: every blob on every transfer is
  verified against its manifest digest; a corrupted or tampered blob is
  discarded, never installed.
- **Bounded parsing**: GGUF headers and JSON blobs are parsed with strict
  size limits; hostile bundles (path traversal, links) are rejected on
  `load`.
- **TLS on by default**: `--insecure-skip-tls-verify` exists for lab
  bring-up and warns loudly; `--ca-file` trusts an internal CA without
  weakening verification.

## Checking a Hugging Face import

`pack hf://org/repo` checks a file against the digest its repository
publishes, refusing a truncated or substituted file before it can be
packed and signed as genuine. A repository publishes that digest for the
files it stores as LFS, which is where the weights and shards live; a
small file served inline, such as `config.json`, publishes none and is
packed with its origin unrecorded rather than invented.

`--oms-key` closes that gap: it checks the repository's own signature over
the files it publishes, so a small file with no digest of its own is still
held against something.

```sh
palan pack hf://org/repo -t llm/model:tag --oms-key model-signing.pub
```

The key is a PEM public key. Given one, palan fetches the `model.sig` the
repository publishes, verifies it, and holds every downloaded file against
what that signature covers, including a file with no published digest of
its own: a file the statement omits, or one whose bytes hash differently,
refuses the whole import before anything is packed. A repository that
publishes no such signature is refused rather than imported unverified.
The signature format is the OpenSSF model-signing format, a Sigstore
bundle carrying a DSSE envelope, and the verifying key is recorded on the
artifact as `io.palan.origin.signer`. Verification is key based; a
keyless signature is not checked.

Because the signature covers files a repository hosts, `--oms-key` only
applies to `hf://` sources: a PATH list holding a local file is refused
rather than packed with part of the artifact unverified.

A host can name that key once instead of relying on every operator to type
`--oms-key` by hand. `verify.sources` names, per pattern, the key a Hugging
Face repository must be signed with:

```yaml
verify:
  sources:
    - pattern: org/**
      oms-key: /etc/palan/org.pub
```

The pattern matches the `org/repo` of an `hf://` reference, never a
revision or a filename, and the first pattern that matches a reference
wins, the same as [Trust policy](#trust-policy)'s `verify.policy`. An
explicit `--oms-key` on the command line always wins outright: when it is
given, no rule is consulted. A malformed `verify.sources` still refuses
every `pack`, including one that passed the flag, because the rules are
read before any source is looked at. Once a rule does match,
everything `--oms-key` already enforces still applies: a repository
publishing no signature is refused, a file the signature omits is refused,
and bytes that hash differently are refused.

`verify.sources` supplies a key; it does not gate. A source that no rule
names is imported with no publisher-signature check at all, exactly as
though `--oms-key` had never been passed, whether that source is a local
`pack ./dir` or a Hugging Face repository nobody has written a rule for
yet. This is the opposite of `verify.policy` under
[Trust policy](#trust-policy), which refuses a reference no pattern
matches: a policy decides who may sign, while this decides only which key
to check when one applies. `verify.sources` set to an empty list is
refused, on the same reasoning that section gives, and deleting the rules
while leaving `verify.sources:` behind reads as no rules at all, so every
import goes unchecked while the file still looks configured. Remove the
key rather than emptying it.

An artifact records one signer, so the key is settled across the whole
argument list before anything downloads. A rule that names a key while a
local file, or a repository no rule names, sits in the same invocation is
refused: the signature covers the files that one repository published, so
anything beside them is covered by nothing, and packing it anyway would put
bytes no signature reaches into an artifact whose manifest names the key as
having vouched for it. Two rules naming different keys for two repositories
in one invocation are refused for the same reason, since only one of the
two could be recorded. Pack them separately, or name every source in one
rule's pattern.

An import under a rule says which repository it held against which key, and
an import no rule names says that nothing was checked, so a pattern that
silently matches nothing does not look like a pattern that matched.

## Signing models

Signatures are cosign-compatible and **work fully offline**, with no
transparency log required. CI verifies them bidirectionally against the
real cosign.

```sh
# One-time: a cosign keypair (palan reads cosign.key/cosign.pub directly)
cosign generate-key-pair

# Sign after pushing (signature lands next to the model in the registry)
palan push  registry.internal/llm/qwen3:8b-q4
palan sign  registry.internal/llm/qwen3:8b-q4 --key cosign.key

# Verify explicitly...
palan verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub
# ...or with cosign itself
cosign verify --key cosign.pub --insecure-ignore-tlog \
  registry.internal/llm/qwen3:8b-q4
```

A signature is accepted only if it validates against the key, **binds the
exact manifest digest**, and claims the expected repository identity.
Copying a valid signature onto a different artifact or repo fails.

## Where a signature lives

A signature is stored under cosign's tag, `sha256-<manifest digest>.sig` in the
model's own repository, and names the model as its subject so registries index
it through the referrers API. Both point at the same manifest: the tag is what
`cosign verify --key` reads, and the subject is what makes a signed model
visible to tooling that discovers artifacts by referrer.

Verification looks under the tag first and asks for referrers only when nothing
is tagged, which is how a signature written by an OCI 1.1 signing tool is
checked:

```bash
COSIGN_EXPERIMENTAL=1 cosign sign --key cosign.key \
  --registry-referrers-mode=oci-1-1 registry.internal/llm/qwen3:8b-q4
palan verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub
```

A signature found that way is held to the same standard as a tagged one.

That identity is the whole reference, **registry host included**. A model
mirrored to another registry keeps its signature but not its identity, so it
does not verify at the new address even with the same repository path and the
same key. Either serve it under the name it was signed as, which for an
air-gapped site usually means the same DNS name resolved differently on each
side, or sign it again where it lands.

## Where a model's files came from

`palan sign` also writes a **source attestation** when the artifact was
packed from a repository rather than from local files: a signed statement
naming, for each layer, the repository it was fetched from, the path within
it, the commit the listing resolved to, and the digest that repository
published for the file. `palan verify` reads it back and holds every layer it
names against the artifact's own manifest, so a statement that vouches for a
layer the artifact does not contain is refused rather than reported as extra
provenance.

```sh
palan pack   hf://Qwen/Qwen3-8B-GGUF -t registry.internal/llm/qwen3:8b-q4
palan push   registry.internal/llm/qwen3:8b-q4
palan sign   registry.internal/llm/qwen3:8b-q4 --key cosign.key
palan verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub
#   Verified registry.internal/llm/qwen3:8b-q4@sha256:...
#     provenance: huggingface.co/Qwen/Qwen3-8B-GGUF@<commit>
```

The statement is an in-toto Statement in a DSSE envelope, predicate type
`https://palan.dev/source/v1`, stored under cosign's `sha256-<digest>.att`
tag and named as a referrer of the model, exactly as a signature is. cosign
reads it:

```sh
cosign verify-attestation --key cosign.pub \
  --type https://palan.dev/source/v1 --insecure-ignore-tlog \
  registry.internal/llm/qwen3:8b-q4
```

It travels with the model through `pull`, `save` and `cp`, and each of those
says whether it did, so an offline host can check the whole chain from what a
repository published to the blobs in its store with no network at all.

Two limits are worth stating plainly. The recorded commit is the one the
repository reported; a source that misreports its own commit is recorded
faithfully as having said so, and the statement proves what palan handled,
not that the source was honest. And a file the repository serves inline with
no published digest, `config.json` among them, is attested with its
repository, path and commit but no published digest, because there was none
to check against. An artifact packed entirely from local files carries no
attestation at all, which is not a failure: there is no upstream to name.

Verifying a model that carries no attestation stays a success. Requiring
one is a separate question from who may sign: the trust policy below names
the identities allowed to sign a reference, and refusing a model that
carries no statement about where its files came from is still ahead.

There is one case worth knowing about, because it is quiet. Verification
answers from the local store whenever the store holds the model and its
signature, without asking a registry that may hold an attestation the store
does not. A store can reach that state through a failed attestation fetch
during a pull, or because someone with write access to it deleted a single
tag: nothing is forged, every signature still verifies, and the model simply
stops having provenance. So `verify` warns when an artifact's own layers
record an upstream source and no statement is found:

```text
Verified registry.internal/llm/qwen3:8b-q4@sha256:...
  source: local store
  WARNING: 3 layer(s) record an upstream source but no attestation is present, so this model's provenance cannot be checked
```

Pulling again brings the statement back. A model packed from local files
records no source and says nothing, so the warning stays meaningful.

## Enforcing verification

Ad hoc, on any command that brings in or runs a model:

```sh
palan pull  registry.internal/llm/qwen3:8b-q4 --verify --verify-key cosign.pub
palan load  -i bundle.tar                     --verify --verify-key cosign.pub
palan run   registry.internal/llm/qwen3:8b-q4 --verify --verify-key cosign.pub
palan serve                                   --verify --verify-key cosign.pub
```

Machine-wide, in `~/.config/palan/config.yaml`:

```yaml
verify:
  required: true
  key: /etc/palan/cosign.pub
```

With `verify.required`, an unsigned or foreign-signed model is refused at
every point it could otherwise get in or get used:

| Command | When the check runs |
|---|---|
| `pull` | before any weight bytes are downloaded |
| `load` | against the bundle, before anything reaches the store |
| `run` | before deciding whether to fetch, so an unsigned model is never downloaded |
| `serve` | when a model is loaded, on first request and again after an eviction |

`serve` checks at load rather than at startup, so a refusal is a `403` on the
request for that model and the rest keep serving. `/v1/models` still lists an
unverified model: listing reports what the store holds, and the refusal
belongs at the point of use.

Checking at serve time matters because the earlier points only cover content
*entering* the store. Anything that writes to the store afterwards would
otherwise be trusted.

This is the recommended configuration once your pipeline signs everything;
palan ships it opt-in.

## Trust policy

`verify.key` names one key trusted for everything. A registry that carries
models from more than one publisher needs a finer answer: which identity
may sign which reference. A trust policy answers it, configured under
`verify.policy` as an ordered list of rules.

A policy decides *who* may sign, not *whether* anything is checked. On a
host where `verify.required` is false and no command passes `--verify`,
`pull`, `load`, `run` and `serve` verify nothing and consult no rule,
which is why the example below turns it on. `palan verify` asks either
way, since checking is the whole of what it does.

```yaml
verify:
  required: true
  policy:
    - pattern: registry.internal/llm/*
      keys:
        - /etc/palan/team-a.pub
    - pattern: registry.internal/**
      keys:
        - /etc/palan/vendor.pub
        - /etc/palan/vendor-next.pub
```

Each rule pairs a pattern with the keys allowed to sign what it matches.
Rules are tried in order, and the first pattern that matches a reference
decides; nothing further down the list is consulted, so an operator writes
the narrowest pattern first and the broadest one last. Above, anything
under `llm/` answers to team-a's key alone; every other repository under
`registry.internal` falls through to the vendor keys.

A pattern matches `registry/repository`, never the tag. A tag moves, so a
policy keyed to one would be re-pointable by whoever can push a tag next,
which is the opposite of what a policy is for.

Within one segment, `*` matches any run of characters that does not cross a
slash, so it matches exactly one path element: `registry.internal/llm/*`
matches `registry.internal/llm/qwen3` but not
`registry.internal/llm/team/qwen3`. A segment that is exactly `**` matches
any number of segments, including none, and it is the only form that can
span a slash. An operator who means "everything under this registry"
writes `registry.internal/**`. Writing `registry.internal/*` instead
matches only a repository with nothing nested under it, so every model one
level deeper is refused: the mistake is a lockout, not a bypass.

A rule may list more than one key. Any one of them verifying is enough, so
rotating a signing key is naming the outgoing and incoming key in the same
rule and dropping the outgoing one once nothing still carries its
signature.

A reference that no pattern matches is refused, and the refusal names the
reference and lists every pattern the policy holds, so a typo or a missing
rule is visible rather than guessed at. `verify.policy` set to an empty list is
refused the same way rather than read as "nothing may sign here": a list
with no rule in it is a half-finished edit far more often than it is a
deliberate lockdown. Deleting the rules but leaving `verify.policy:` behind
with nothing after it reads as no policy at all, and `verify.key` governs
again, so remove the whole block rather than emptying it. A pattern built
from more than four `**` segments is
also refused, which keeps matching a bounded operation regardless of what
a rule author writes.

A policy is read when a reference is about to be verified, not when the
process starts, so a rule with a pattern the loader cannot accept is
reported at the first verification rather than at launch. On a host where
`verify.required` is false and no command passes `--verify`, or on a
command given `--verify-key`, nothing verifies and the policy is never
read, so a malformed one sits unreported until something asks it a
question. `verify.sources` behaves the other way round: `pack` reads it
before looking at any source, so a malformed one refuses every import
straight away.

The keys a rule names are read from disk each time a reference is
verified rather than held from startup, so replacing or removing a key
file changes what verifies without restarting `serve`. That takes effect
the next time a model is loaded, not on the next request: `serve` checks
at load, so a model already resident keeps answering under the key it was
admitted with until it is evicted. Removing a key file is not a way to cut
off a model that is already serving.

Holding a model's source attestation to the identity that signed the model
is something `palan verify` does. The gates at `pull`, `load`, `run` and
`serve` check the signature against the policy and stop there, so a model
whose attestation was signed by a different key the same rule allows passes
them and is caught by an explicit `palan verify`.

Configuring `verify.policy` replaces `verify.key` outright: once a policy
is set, `verify.key` is never consulted, matched or not. `--verify-key` on
the command line overrides both for that one invocation, since a key
someone typed is a deliberate act that the standing configuration yields
to. On `sign` and `verify`, where the key is the whole point of the
command, the same flag is spelled `--key`.

A model's source attestation, where one exists, is checked against the
identity that verified its signature, not against every key the policy
allows for that reference: a statement signed by a different holder does
not pass just because that holder also appears elsewhere in the same
policy.

## Keyless signatures

A keyless signature names its signer instead of naming a key. There is no
key file to distribute: the signer authenticates to an OpenID provider,
receives a certificate that lives about ten minutes, signs with it, and the
signature is recorded in a public transparency log.

Checking one normally means asking a certificate authority whether the
certificate was issued and asking the log whether the signature was
recorded. An air-gapped host can ask neither, so palan checks a signature
that carries the answers with it: the certificate, the log entry, and an
inclusion proof showing that entry really is in the log. What cannot travel
with the artifact is the decision about whom to trust, so that is pinned
separately, as a file.

palan verifies keyless signatures and does not make them. Signing that way
needs the services this feature exists to avoid depending on.

### Pinning a root

The pinned file is a Sigstore trusted root: which certificate authorities
may issue signing certificates, and which transparency logs are believed.
For the public Sigstore instance, `cosign` will write one:

```sh
cosign trusted-root create   --fulcio="url=https://fulcio.sigstore.dev,certificate-chain=fulcio.pem"   --rekor="url=https://rekor.sigstore.dev,public-key=rekor.pub,start-time=2021-01-12T00:00:00Z"   --out /etc/palan/sigstore-root.json
```

Copy that file to the disconnected host. It is public material, not a
secret, and it is the thing an operator decides on: everything else arrives
with the artifact and is checked against it.

### Naming who may sign

A policy rule names identities where it would otherwise name keys, and the
root they are checked against:

```yaml
verify:
  required: true
  policy:
    - pattern: registry.internal/vendor/**
      trust-root: /etc/palan/sigstore-root.json
      identities:
        - subject: https://github.com/vendor/models/.github/workflows/release.yml@refs/tags/*
          issuer: https://token.actions.githubusercontent.com
    - pattern: registry.internal/**
      keys:
        - /etc/palan/team.pub
```

The subject is what the certificate says its holder is: an email address
for a person, a URL for a workload. `*` in a subject stands for any run of
characters, which is what makes a workflow identity usable: it carries the
git ref that built it, so it changes with every release and an exact name
would have to be edited each time.

A subject pattern must name, without a wildcard, the part of an identity
its holder cannot choose. In an address that is the domain after the last
`@`; in a URL it is the host. The local part of an address and the path of
a workflow are the signer's to pick, so a pattern that wildcards the
authority matches identities belonging to whoever cares to mint one.

```yaml
# Accepted
*@example.com                                       # any address at that domain
*@*.example.com                                     # and at its subdomains
https://forge.example/org/repo/.github/workflows/*  # any workflow in that repository
https://gitea/acme/repo/*                           # a host needs no dot
spiffe://prod/ns/ci/sa/builder                      # exact: it can only match itself

# Refused when the config loads
*                                                   # everything
*@*                                                 # any address anywhere
*/.github/workflows/release.yml@refs/tags/*         # any repository with that file
*/.github/workflows/release.yml@refs/tags/v1.0.0    # and so is the literal version
*@refs/heads/main                                   # a git ref is not a domain
https://*.example.com/org/repo/*                    # matching ignores "/", so this
                                                    # reaches other hosts too
*://forge.example/org/repo/*                        # a wildcard before the scheme
                                                    # unanchors the whole pattern
*@*example.com                                      # extends a domain rather than
                                                    # anchoring one: evilexample.com
https://github.com/*                                # a forge is not a publisher: one
                                                    # provider serves every account
*@*.com                                             # a suffix everybody shares is
                                                    # not a domain anybody holds
```

The workflow entries are the ones worth reading twice, because they are what
anyone would write first. Anchoring on the workflow file and wildcarding the
organisation pins nothing at all: the path is the signer's to choose, and
under a provider every repository on a forge shares, any repository with a
`release.yml` satisfies it. Pinning the release tag as well does not help,
since the tag is equally the signer's to choose.

Naming only the host does not help either, which is why `https://github.com/*`
is refused. One OpenID provider serves every account on a public forge, so the
host names a company rather than a signer, and a stranger with a free account
satisfies it. A URL pattern has to name the host **and** the first path
segment, which is where a forge puts the account.

Name the **host and the repository**, and wildcard the ref:

```yaml
subject: https://github.com/org/repo/.github/workflows/release.yml@refs/tags/*
```

An exact subject, one with no `*` at all, is always accepted: it can only
match itself.

A pattern is also held to its own shape. An address pattern is compared only
against an address and a URL pattern only against a URL, because matching is
plain text and a git ref may contain both `@` and `.`: without that,
`*@example.com` would reach a workflow identity built from a tag named
`v1@example.com`.

A certificate naming its holder more than once is refused, since there is
no reading of "who signed this" that returns two answers.

The issuer is the OpenID provider that authenticated the holder, and it is
matched exactly. A subject on its own is a name any provider can mint, so
without the issuer a signer authenticated anywhere at all would pass as the
signer authenticated where it matters. A rule naming a subject and no
issuer is refused when the config loads.

A rule may name keys and identities together. That is what a migration
looks like from the inside: signatures made either way are accepted while
publishers move between them, and the rule narrows again afterwards.

`trust-root` is pinned per rule rather than once for the whole file,
because two registries need not draw on the same Sigstore instance. Naming
identities without a root, or a root without identities, is refused when
the config loads: neither half does anything alone, and a root nothing
reads would leave somebody believing they had pinned something.

A subject of `*` is refused. It admits every identity the issuer ever
certified, which is not a policy.

### What is checked, and in what order

```sh
palan verify registry.internal/vendor/qwen3:8b-q4
# Verified registry.internal/vendor/qwen3:8b-q4@sha256:...
#   source: local store
#   signer: https://github.com/vendor/models/.github/workflows/release.yml@refs/tags/v2.1.0 (via https://token.actions.githubusercontent.com), logged at 2026-08-30T09:14:02Z as entry 421889301
```

The signer is reported because it is the one thing the result establishes
that the configuration did not already state. With a key, the identity is
the file you named; here it is whatever the certificate turned out to say,
and the policy pattern it matched may be broader than the signer it
admitted.

In order: the signature is checked against its own certificate; the log's
own signature over the entry is checked, which is what establishes when the
signature was recorded; the entry is checked to be in a log the pinned root
names, by rebuilding the log root from the inclusion proof and requiring the
log's signed checkpoint to agree; the proven entry is checked to be about
this signature rather than some other entry in the same log; the certificate
is checked to chain to a pinned authority *as of the moment the log recorded
the signature*; the signer is checked against the rule; and the signed
statement is checked to be about this artifact's digest.

Two different signatures by the log are involved and they prove different
things. The **checkpoint** signs the log's size and its root, so it proves
an entry is in the log and says nothing about when: it carries no date, and
neither do the entry's bytes. The **signed entry timestamp** signs the
entry's bytes together with the date, the log's identity and the entry's
position, and it is the only thing that dates a signature.

That distinction decides whether certificate expiry means anything. A
keyless certificate is expired by the time anyone verifies it, so checking
it against the present would refuse every keyless signature ever made; it is
checked against log time instead. If log time were taken from the bundle
unchecked, whoever wrote the bundle would choose it, and a certificate that
can be checked against any moment does not expire at all. Someone holding
key material recovered long after the fact could then sign a model today and
date it inside the ten minutes when the certificate was live.

So an entry carrying no signed timestamp is refused, rather than accepted
with the date it states.

Holding the proven entry against the signature in hand is the check that an
inclusion proof cannot make for itself. A valid proof shows that *some*
entry is in the log, and a log holds millions.

### Carrying one across a gap

A keyless signature is attached to the model as a referrer and carries no
tag of its own, which is how the tools that write one publish it. It is
always found that way, by asking what refers to the model, and never by a
tag: a tag is something anybody with push access can create, and it would
otherwise decide which signature gets checked.

For the same reason every signature attached to a model is tried, and every
one travels. An artifact can carry several, which is ordinary during a key
rotation and is also what somebody with push access does to shadow a real
one. `pull` brings them all into the store, `save` puts them all in the
transfer bundle, and `load` imports them.

A model is accepted when **any one** of its signatures satisfies the policy,
not when all of them do. Requiring all would mean anyone able to push to the
repository could attach one broken signature and make the model permanently
unverifiable for everybody. Trying all of them is what stops that same person
choosing which signature gets examined; the ones that do not verify are
ignored rather than held against the model.

```sh
palan pull registry.internal/vendor/qwen3:8b-q4
# Keyless signature stored alongside the model

palan save registry.internal/vendor/qwen3:8b-q4 -o qwen3.tar
# Included 1 keyless signature(s)
```

On the far side, `palan verify` and `palan load --verify` work with no
registry at all, given the trusted root on disk.

If a keyless signature could not be carried, `pull` says so and keeps the
model. The model is still there; what is gone is the ability to check it
later without a registry.

### What is not checked

The signed certificate timestamp inside the certificate is not verified.
It would catch a certificate authority that issued a certificate without
logging it, which is a compromise of an authority you have already chosen
to pin.

A source attestation is checked against the key that signed the model, and
a keyless signature supplies an identity rather than a key. A model
verified this way whose layers record upstream sources therefore reports
its provenance as unchecked:

```text
  WARNING: 2 layer(s) record an upstream source, and a source attestation
  is checked against the key that signed the model, so a model verified by
  a keyless signature has its provenance left unchecked
```

Only the Sigstore bundle form is read. `cosign sign` writes it with
`--new-bundle-format`; without that flag it attaches the certificate and a
signed entry timestamp instead, and a signed entry timestamp is the log's
promise to record an entry rather than evidence that it did. palan refuses
that form rather than accept it as though the two were the same.

## Registry authentication

- `palan login REGISTRY` validates credentials and stores them in the
  Docker credentials store (a credential helper when configured; plaintext
  `~/.docker/config.json` otherwise; prefer a helper).
- No plaintext password flag exists; use the prompt or `--password-stdin`.
- Kubernetes workloads should use OIDC workload identity against zot
  (projected ServiceAccount tokens) instead of static secrets. See the
  [Kubernetes guide](kubernetes.md).

## Serving

- `palan serve` binds `:11500`; child llama-server processes bind loopback
  only and are never directly exposed.
- Optional bearer auth: `serve.bearer-token` in the config (compared in
  constant time).

## Not implemented yet (tracked on the roadmap)

- Keyless (Fulcio/Rekor) *signing*, which requires online infrastructure.
  Verifying a keyless signature is implemented, and needs none.
- OIDC device-flow login from the CLI. `palan login` takes a username with a
  prompt or `--password-stdin`, and stores the result in the Docker credentials
  store.

Bundle verification used to sit in this list. It does not any more:
`palan load --verify` refuses any model in a bundle whose signature does not
check out, and `palan verify` reads a signature from the local store when it
holds one, naming the source so a local answer is never mistaken for a remote
one (ADR-0007). Verifying against a registry after import is not a workaround
an air-gapped host can use, because there is no registry there to ask.
