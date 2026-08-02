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

That identity is the whole reference, **registry host included**. A model
mirrored to another registry keeps its signature but not its identity, so it
does not verify at the new address even with the same repository path and the
same key. Either serve it under the name it was signed as, which for an
air-gapped site usually means the same DNS name resolved differently on each
side, or sign it again where it lands.

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

## Out of scope in v0.1 (tracked on the roadmap)

- Keyless (Fulcio/Rekor) signing, which requires online infrastructure.
- OIDC device-flow login from the CLI.
- Signature verification for `save`/`load` bundles (verify against the
  registry after import instead).
