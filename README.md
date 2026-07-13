# moci

> Pull, push, pack, and **serve** GGUF models as standard OCI artifacts —
> daemonless, air-gap-first, one static binary.

[![CI](https://github.com/aimd54/moci/actions/workflows/ci.yml/badge.svg)](https://github.com/aimd54/moci/actions/workflows/ci.yml)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

moci treats local LLMs the way `docker` treats images: models are
[CNCF ModelPack](https://modelpack.org) artifacts in **any** OCI 1.1 registry
(zot, Harbor, distribution, GHCR, …), served locally through managed
llama.cpp `llama-server` processes behind one OpenAI-compatible endpoint.

Every neighbouring tool concedes one leg of the triangle moci occupies:

|                                | standard OCI registries | daemonless | managed multi-model serving |
|--------------------------------|:---:|:---:|:---:|
| Ollama                         | ✗ (own dialect) | ✓ | ✓ |
| RamaLama / Docker Model Runner | ✓ | ✗ (needs a container engine) | ✓ |
| modctl / KitOps / ORAS         | ✓ | ✓ | ✗ |
| **moci**                       | ✓ | ✓ | ✓ |

Think of moci as **the runtime companion to
[modctl](https://github.com/modelpack/modctl)**: packaging is
spec-identical (round-trips against `modctl`, `oras`, and `cosign` are part
of CI), and moci adds the layer they stop at — pulling *and serving*, in
places where no Docker daemon exists and no internet ever will.

## Highlights

- **Transfer**: pull/push/cp against any OCI registry, concurrent and
  digest-verified; interrupted pulls **resume across process restarts**
  (HTTP Range). Blobs dedup across tags and repositories (cross-repo mount).
- **Reproducible packing**: the same GGUF in ⇒ the same digest out.
  Metadata (architecture, quantization, context length, license) is read
  from the GGUF header into the ModelPack config.
- **Serving**: `moci run` for a REPL; `moci serve` for an OpenAI-compatible
  router on `:11500` — lazy load, idle unload, memory-budget LRU eviction
  (two models on a 10 GB GPU evict instead of OOMing), SSE streaming,
  Prometheus metrics.
- **Zero-copy**: weight layers are raw, so the blob in the store *is* the
  file `llama-server` mmaps. No unpack step, no double storage.
- **Air gap**: `save`/`load` tar bundles (standard OCI layout), direct
  registry-to-registry `cp`, and llama-server builds distributed as OCI
  artifacts through the same registries as the models.
- **Supply chain**: cosign-compatible key-based signing that works fully
  offline; `moci pull --verify` refuses unsigned or foreign-signed models
  before a single weight byte moves.
- **Kubernetes**: init-container puller image, image volumes (K8s ≥ 1.36)
  via the car profile, KServe modelcars — see
  [`deploy/k8s-examples/`](deploy/k8s-examples/README.md).

## Quickstart

```sh
# A throwaway local registry
docker run -d --rm -p 5000:5000 ghcr.io/project-zot/zot-linux-amd64:v2.1.18

# Pack a GGUF you already have, push it
moci pack qwen3-8b-instruct-q4_k_m.gguf -t localhost:5000/llm/qwen3:8b-q4 \
  --plain-http --ctx 8192 --push

# Anywhere else: pull and chat (llama-server in PATH, or `moci runtime pull`)
moci pull localhost:5000/llm/qwen3:8b-q4 --plain-http
moci run localhost:5000/llm/qwen3:8b-q4 --prompt "Say hi"

# Or serve everything you have behind one OpenAI endpoint
moci serve
curl localhost:11500/v1/chat/completions -d '{
  "model": "localhost:5000/llm/qwen3:8b-q4",
  "messages": [{"role": "user", "content": "Say hi"}]
}'
```

Full walkthrough: [docs/quickstart.md](docs/quickstart.md).

## Documentation

| Document | What it covers |
| --- | --- |
| [Quickstart](docs/quickstart.md) | zero to served model in ~5 minutes |
| [Air-gap guide](docs/guides/air-gap.md) | sneakernet bundles, mirroring, offline verification |
| [Kubernetes guide](docs/guides/kubernetes.md) | init puller, image volumes, KServe |
| [Security guide](docs/guides/security.md) | signing, verification policy, TLS, auth |
| [CLI reference](docs/reference/moci.md) | generated from the command tree (`make docs`) |
| [Configuration](docs/reference/configuration.md) | config file, env vars, precedence |
| [Registry deployment](deploy/zot/README.md) | zot + MinIO + OIDC reference setup |
| [Design document](docs/design/oci-llm-distribution.md) | the why behind everything |
| [ADRs](docs/adr/README.md) | decisions and their reasoning |
| [Roadmap](docs/roadmap.md) | shipped vs. planned |

## Status

Pre-1.0, under active development. Scope is deliberately sharp: **GGUF +
llama.cpp** (safetensors/vLLM are format-compatible later, not now).
`moci` is a working codename and will be renamed before wide release
(design §16.1). Interoperability is a contract, not an aspiration —
artifacts must round-trip against `modctl` and `oras`, and signatures
against `cosign`, in CI, forever.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md) — DCO sign-off and Conventional
Commits required. Security reports: [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
