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

- Keyless (Fulcio/Rekor) signing, which requires online infrastructure.
- OIDC device-flow login from the CLI. `palan login` takes a username with a
  prompt or `--password-stdin`, and stores the result in the Docker credentials
  store.

Bundle verification used to sit in this list. It does not any more:
`palan load --verify` refuses any model in a bundle whose signature does not
check out, and `palan verify` reads a signature from the local store when it
holds one, naming the source so a local answer is never mistaken for a remote
one (ADR-0007). Verifying against a registry after import is not a workaround
an air-gapped host can use, because there is no registry there to ask.
