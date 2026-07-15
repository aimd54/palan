# Air-gapped model distribution with palan

palan is air-gap-first: every artifact — models *and* the llama-server
runtimes that serve them — moves through standard OCI registries or
offline bundles, digest-verified end to end.

## The cast

- **Connected side**: a machine that can reach upstream sources
  (Hugging Face, ghcr.io) and the connected-side registry.
- **Air-gapped side**: the internal registry (e.g. zot, see
  [`deploy/zot/`](../../deploy/zot/README.md)) and the workstations/cluster
  that pull from it.

## 1. Package on the connected side

```sh
# Model: GGUF + chat template + license, with provenance annotations
palan pack qwen3-8b-instruct-q4_k_m.gguf chat_template.jinja LICENSE \
  -t connected.example/llm/qwen3:8b-instruct-q4_k_m \
  --source https://huggingface.co/Qwen/... \
  --ctx 8192 --ngl 99 \
  --profile both --push

# Runtime: a pinned llama-server build (from llama.cpp releases)
palan runtime pack llama-server libggml.so \
  -t connected.example/runtimes/llama-server:b4567-cuda12 \
  --build b4567 --flavor cuda12 --push
```

Packing is reproducible: identical inputs give identical digests, so
re-packing on both sides of the gap yields verifiable equality.

## 2. Cross the gap

Pick per your topology:

### Physical transfer (no network path at all)

```sh
# Connected side — one bundle can carry several refs, blobs deduplicated:
palan pull connected.example/llm/qwen3:8b-instruct-q4_k_m
palan save connected.example/llm/qwen3:8b-instruct-q4_k_m \
          connected.example/runtimes/llama-server:b4567-cuda12 \
          -o transfer.tar
# … carry transfer.tar across …
# Air-gapped side:
palan load -i transfer.tar
palan push registry.internal/llm/qwen3:8b-instruct-q4_k_m   # after re-tagging, see note
```

The bundle is a tar of a standard OCI image layout — inspectable with
`oras`, `tar tf`, or any OCI tool. Note: refs keep their original registry
host inside the bundle; re-tag on import side with a pull/push pair or use
`palan cp` when a one-way path exists.

### One-way network path (connected side → offline side)

```sh
palan cp connected.example/llm/qwen3:8b-instruct-q4_k_m \
        registry.internal/llm/qwen3:8b-instruct-q4_k_m
```

**Continuous mirroring**: zot's `sync` extension pulls selected repos from
the connected-side zot on a schedule — see the registry runbook.

## 3. Serve inside

```sh
palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12
palan pull registry.internal/llm/qwen3:8b-instruct-q4_k_m
palan serve --keep-loaded registry.internal/llm/qwen3:8b-instruct-q4_k_m
# → OpenAI-compatible endpoint on :11500, metrics on /metrics
```

Interrupted pulls resume where they stopped — including across reboots —
via HTTP Range requests against the registry.

## Integrity and provenance across the gap

- Every blob transfer is digest-verified; a bundle tampered in transit
  fails on load/pull.
- `io.palan.origin.sha256` ties the artifact to the upstream file it was
  packed from; `org.opencontainers.image.source` records where.
- Cosign signatures travel as OCI referrers next to the model, so
  signature verification works inside the gap without any external
  service (key-based signing; see the security guide once signing lands).
