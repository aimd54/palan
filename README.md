# palan

> **Serve** GGUF models straight from any OCI registry.
> Daemonless, runs offline, one static binary.

[![CI](https://github.com/aimd54/palan/actions/workflows/ci.yml/badge.svg)](https://github.com/aimd54/palan/actions/workflows/ci.yml)
[![OpenSSF Scorecard](https://api.scorecard.dev/projects/github.com/aimd54/palan/badge)](https://scorecard.dev/viewer/?uri=github.com/aimd54/palan)
[![Go Reference](https://pkg.go.dev/badge/github.com/aimd54/palan.svg)](https://pkg.go.dev/github.com/aimd54/palan)
[![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)](LICENSE)

palan treats local LLMs the way `docker` treats images: models are
[CNCF ModelPack](https://modelpack.org) artifacts in **any** OCI 1.1 registry
(zot, Harbor, distribution, GHCR, ...), served locally through managed
llama.cpp `llama-server` processes behind one OpenAI-compatible endpoint.

A *palan* is the French block-and-tackle hoist for lifting heavy loads.
This one pulls weights.

Every neighbouring tool concedes one leg of the triangle palan occupies:

|                                | standard OCI registries | daemonless | managed multi-model serving |
|--------------------------------|:---:|:---:|:---:|
| Ollama                         | ✗ (own dialect) | ✓ | ✓ |
| RamaLama / Docker Model Runner | ✓ | ✗ (needs a container engine) | ✓ |
| modctl / KitOps / ORAS         | ✓ | ✓ | ✗ |
| **palan**                       | ✓ | ✓ | ✓ |

Artifacts are plain ModelPack. They round-trip against
[modctl](https://github.com/modelpack/modctl), `oras`, and `cosign` in CI,
so whatever packs a model for an OCI registry can feed palan, and whatever
reads OCI artifacts can read what palan writes. Weights stay raw and
mmap-ready, the inference engine arrives from the same registry as the
models, and one static binary runs them behind an OpenAI endpoint, in
places where no container engine exists and no internet ever will.

## Highlights

- **Transfer**: pull/push/cp against any OCI registry, concurrent and
  digest-verified; interrupted pulls **resume across process restarts**
  (HTTP Range). Blobs dedup across tags and repositories (cross-repo mount).
- **Reproducible packing**: the same GGUF in ⇒ the same digest out.
  Metadata (architecture, quantization, context length, license) is read
  from the GGUF header into the ModelPack config.
- **Serving**: `palan run` for a REPL; `palan serve` for an OpenAI-compatible
  router on `:11500`: lazy load, idle unload, memory-budget LRU eviction
  (two models on a 10 GB GPU evict instead of OOMing), SSE streaming,
  Prometheus metrics.
- **Runtime distribution**: `llama-server` builds travel as OCI artifacts
  through the same registry as the weights: version-pinned per release,
  signable like any other artifact, and swappable without rebuilding palan.
  Offline hosts get engine upgrades through the channel they already have.
- **Zero-copy**: weight layers are raw, so the blob in the store *is* the
  file `llama-server` mmaps. No unpack step, no double storage.
- **Air gap**: `save`/`load` tar bundles (standard OCI layout) and direct
  registry-to-registry `cp`; models and runtimes travel the same two paths.
- **Supply chain**: cosign-compatible key-based signing that works fully
  offline; `palan pull --verify` refuses unsigned or foreign-signed models
  before a single weight byte moves.
- **Kubernetes**: init-container puller image, image volumes (K8s ≥ 1.36)
  via the car profile, KServe modelcars. See
  [`deploy/k8s-examples/`](deploy/k8s-examples/README.md).

## Quickstart

```sh
# A throwaway local registry
docker run -d --rm -p 5000:5000 ghcr.io/project-zot/zot-linux-amd64:v2.1.18

# Pack a GGUF you already have, push it
palan pack qwen3-8b-instruct-q4_k_m.gguf -t localhost:5000/llm/qwen3:8b-q4 \
  --plain-http --ctx 8192 --push

# Anywhere else: pull and chat (llama-server in PATH, or `palan runtime pull`)
palan pull localhost:5000/llm/qwen3:8b-q4 --plain-http
palan run localhost:5000/llm/qwen3:8b-q4 --prompt "Say hi"

# Or serve everything you have behind one OpenAI endpoint
palan serve
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
| [Architecture](docs/architecture.md) | how the pieces fit together |
| [Air-gap guide](docs/guides/air-gap.md) | offline bundles, mirroring, offline verification |
| [Kubernetes guide](docs/guides/kubernetes.md) | init puller, image volumes, KServe |
| [Security guide](docs/guides/security.md) | signing, verification policy, TLS, auth |
| [CLI reference](docs/reference/palan.md) | generated from the command tree (`make docs`) |
| [Configuration](docs/reference/configuration.md) | config file, env vars, precedence |
| [Registry deployment](deploy/zot/README.md) | zot + MinIO + OIDC reference setup |
| [ADRs](docs/adr/README.md) | decisions and their reasoning |
| [Roadmap](docs/roadmap.md) | shipped vs. planned |

## Status

Pre-1.0, under active development. Scope is deliberately sharp: **GGUF +
llama.cpp** (safetensors/vLLM are format-compatible later, not now).
`palan` is the project's release name; early ADRs predate it and use the
working codename `moci`
([ADR-0006](docs/adr/0006-rename-to-palan.md)).
CI enforces interoperability on every commit: artifacts round-trip against
`modctl` and `oras`, and signatures against `cosign`.

## Contributing

See [CONTRIBUTING.md](CONTRIBUTING.md); DCO sign-off and Conventional
Commits are required. Security reports: [SECURITY.md](SECURITY.md).

## License

[Apache-2.0](LICENSE)
