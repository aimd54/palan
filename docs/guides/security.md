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

Verifying a model that carries no attestation stays a success. Requiring one
is a policy question, and the policy layer is on the roadmap.

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
