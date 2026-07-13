# Security guide

Model weights are attacker-controlled, code-adjacent inputs (design §11):
they are mmapped by native code and their templates steer your agents. moci
treats their distribution accordingly.

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

Signatures are cosign-compatible and **work fully offline** — no
transparency log required, which the air gap demands. Verified
bidirectionally against the real cosign in CI.

```sh
# One-time: a cosign keypair (moci reads cosign.key/cosign.pub directly)
cosign generate-key-pair

# Sign after pushing (signature lands next to the model in the registry)
moci push  registry.internal/llm/qwen3:8b-q4
moci sign  registry.internal/llm/qwen3:8b-q4 --key cosign.key

# Verify explicitly…
moci verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub
# …or with cosign itself
cosign verify --key cosign.pub --insecure-ignore-tlog \
  registry.internal/llm/qwen3:8b-q4
```

A signature is accepted only if it validates against the key, **binds the
exact manifest digest**, and claims the expected repository identity —
copying a valid signature onto a different artifact or repo fails.

## Enforcing verification on pull

Ad hoc:

```sh
moci pull registry.internal/llm/qwen3:8b-q4 --verify --verify-key cosign.pub
```

Fleet-wide, in `~/.config/moci/config.yaml`:

```yaml
verify:
  required: true
  key: /etc/moci/cosign.pub
```

With `verify.required`, **every** pull checks the signature before any
weight bytes are downloaded; unsigned or foreign-signed models are refused.
This is the recommended posture once your pipeline signs everything
(design §16.2 ships it opt-in for v0.1).

## Registry authentication

- `moci login REGISTRY` validates credentials and stores them in the
  Docker credentials store (a credential helper when configured; plaintext
  `~/.docker/config.json` otherwise — prefer a helper).
- No plaintext password flag exists; use the prompt or `--password-stdin`.
- Kubernetes workloads should use OIDC workload identity against zot
  (projected ServiceAccount tokens) instead of static secrets — see the
  [Kubernetes guide](kubernetes.md).

## Serving

- `moci serve` binds `:11500`; child llama-server processes bind loopback
  only and are never directly exposed.
- Optional bearer auth: `serve.bearer-token` in the config (compared in
  constant time).

## Out of scope in v0.1 (tracked on the roadmap)

- Keyless (Fulcio/Rekor) signing — requires online infrastructure.
- OIDC device-flow login from the CLI.
- Signature verification for `save`/`load` bundles (verify against the
  registry after import instead).
