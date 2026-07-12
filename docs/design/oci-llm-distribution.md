# moci — OCI-native distribution and serving for local LLMs

**Design document v0.2 — July 2026**
**Status:** draft, pre-M0
**Working name:** `moci` (model + OCI) — collision check done 2026-07: acceptable as codename, **rename before public release** (see Open Questions §16.1)

**Changelog v0.2:** repositioned relative to modctl (layered, not competing); M0 gate extended with modctl-as-dependency evaluation (ADR-005); name-availability findings recorded; M1 estimate and risk table updated accordingly.
**Edition note:** public edition — environment-specific context from the original working document has been generalized; content is otherwise unchanged.

---

## 1. Summary

`moci` is a single-binary, daemonless CLI that treats GGUF models the way `docker`/`podman` treat images: `pull`, `push`, `ls`, `run`, `serve` against **any standard OCI registry**, then serves them locally through `llama.cpp`'s `llama-server` behind an OpenAI-compatible endpoint.

The critical design decision is what **not** to build: the registry itself. The OCI Distribution Spec is a solved problem with excellent self-hostable implementations (zot, distribution, Harbor), all of which store arbitrary artifacts — including multi-GB model weights — with content addressing, deduplication, resumable transfers, auth, and replication for free. `moci` is only the client and serving layer. The artifact format follows the CNCF **ModelPack** specification (`application/vnd.cncf.model.*` media types) for ecosystem interoperability rather than inventing yet another format.

This replaces the current bespoke stack (FastAPI registry + MinIO + `llm-pull.py`/`llm-push.py`): MinIO stays as the storage backend (via the registry's S3 driver), the FastAPI service and custom scripts are retired.

---

## 2. Context and motivation

The existing air-gapped LLM distribution system works, but has structural limits inherent to a bespoke protocol:

- No content addressing: no dedup between quantizations sharing blobs, no integrity-by-construction, no resumable pulls.
- No ecosystem: nothing else can pull from it — not Kubernetes, not CI, not `oras`, not signing tools.
- Every feature (auth, GC, mirroring, UI) must be hand-built on FastAPI.
- No signing or provenance story.

Meanwhile the industry converged (2024–2026) on OCI registries as the distribution substrate for models: Docker Model Runner packages models as OCI artifacts, CNCF ModelPack standardizes the format, Kubernetes 1.36 shipped image volumes as GA specifically citing AI/ML model mounting, and zot/Harbor natively store and sign these artifacts. Aligning with this substrate means most of the hard problems disappear.

Secondary motivation: the same registry can distribute **other model families** — e.g. fine-tuned OCR/HTR models from adjacent projects — with the same signing, versioning, and air-gap story. One distribution plane for all model weights.

---

## 3. Goals and non-goals

### Goals

| # | Goal |
|---|------|
| G1 | Pull/push GGUF models to/from **any** OCI 1.1-conformant registry (zot, Harbor, distribution, GHCR, ECR…) |
| G2 | **ModelPack-compliant** artifacts; interoperable with `modctl`, KitOps, ORAS, podman-artifact |
| G3 | **Daemonless single static binary** — no Docker/Podman required on the client (the gap vs. RamaLama/DMR) |
| G4 | Serve pulled models via `llama-server` behind one OpenAI-compatible endpoint with multi-model routing, lazy load, idle unload |
| G5 | Air-gap first: offline export/import bundles, registry-to-registry copy, DMZ mirroring |
| G6 | Kubernetes-native consumption: init-container puller, image volumes, KServe `oci://` |
| G7 | Cosign signing/verification and provenance annotations (source URL, original SHA-256, license) |
| G8 | Distribute the **inference runtimes themselves** (per-platform `llama-server` builds) as OCI artifacts through the same registry |

### Non-goals

- Building a registry server (reuse zot/distribution/Harbor).
- Training, fine-tuning, or model conversion beyond GGUF packing (HF→GGUF conversion stays in llama.cpp tooling).
- safetensors / vLLM serving (possible phase 2; the artifact format already supports it since ModelPack is format-agnostic).
- Replacing LiteLLM: `moci serve` is an OpenAI-compatible *backend* that LiteLLM can route to, exactly like `llama-server` today.
- Windows support in v0.x (Linux + macOS arm64).
- Multi-tenant / SaaS concerns.

---

## 4. Prior art and the build-vs-adopt decision

This space is crowded. An honest map, as of mid-2026:

| Tool | Registry story | Serving | Daemonless? | Notes |
|---|---|---|---|---|
| **Ollama** | Own dialect of OCI distribution; third-party push/pull *works* (zot, `registry:2`) but is unsupported: `--insecure` quirks, no way to change the default registry, auth against Harbor-style token servers broken (issues #2745, #7244, #4204, #9409) | llama.cpp fork, own API + OpenAI compat | Yes (own daemon) | Closest UX, weakest custom-registry story |
| **RamaLama** (containers org) | First-class `oci://`, `ollama://`, `huggingface://` transports | llama.cpp / vLLM / MLX in containers; router mode for multi-model | **No** — needs Podman/Docker; OCI transport explicitly unsupported with `--nocontainer` | Closest overall match to this design |
| **Docker Model Runner** | OCI artifacts, any registry incl. private; HF pull with on-the-fly conversion | llama.cpp, OpenAI API on :12434, 5-min idle unload | **No** — needs Docker Desktop/Engine | Its artifact spec ≈ ModelPack-adjacent; harmonization announced |
| **KitOps / modctl** (ModelPack impls) | Any OCI registry; `kit pack --use-model-pack`; modctl: `build`/`pull`/`push` + Modelfile | Packaging/transfer only — **no run/serve layer** | Yes | Not competitors: the layer `moci` should *ride on*, not duplicate (see below) |
| **ORAS / podman artifact** | Generic artifact push/pull | None | Yes | The plumbing; no model semantics, no serving |
| **LocalAI / llama-swap** | Partial / none | Multi-model swap proxies | Varies | Serving-side prior art for the router |

**The actual gap** `moci` fills: *daemonless* + *standard OCI* + *managed multi-model llama.cpp serving* in one static binary. Every existing tool concedes one leg of that triangle: Ollama concedes standard OCI, RamaLama and DMR concede daemonless, ORAS/modctl concede serving. For air-gapped workstations and thin K8s init containers, daemonless matters.

**Relationship to modctl (v0.2).** In container terms: modctl is skopeo/buildah for models; `moci` aims to be `podman run`. modctl's scope ends at build/pull/push — no runtime, no llama-server supervision, no OpenAI router — so the serving layer (G4, §9) doesn't overlap at all. The transfer/pack layer (G1–G2, §8) *does* overlap and should be **delegated, not duplicated**: modctl ships a `pkg/` directory alongside `internal/` and publishes GoDoc, so at least part of it is importable as a library. Note also that the ModelPack ecosystem explicitly embraces parallel implementations (KitOps and modctl coexist as official tools), so residual overlap is sanctioned — but for a solo maintainer, upstreaming beats reimplementing every time.

**M0 gate (decide before writing code):** spend one day attempting the workflow with existing tools only — zot + `ollama push/pull --insecure`, and zot + RamaLama with Podman. If either is *actually good enough* for the internal use case, adopt it and reduce this project to (a) the zot deployment and (b) at most a thin wrapper. Additionally (**ADR-005**): evaluate modctl as the transfer/pack dependency — determine whether the `build`/`pull`/`push` logic lives in importable `pkg/` packages or is locked behind `internal/`. If locked, proposing the library refactor upstream is itself the flagship first contribution, and M1–M2 shrink to glue code either way. Build `moci`'s own transfer layer only if both paths fail. Record outcomes as ADR-001/ADR-005. (Prediction: Ollama's dialect will chafe on auth and naming; RamaLama will chafe on the container-engine requirement in the air-gapped segment. But verify.)

### Is it worth open-sourcing?

Qualified yes — and v0.2 sharpens the pitch: `moci` is **the missing daemonless local runner of the ModelPack ecosystem**, which today has a spec, two packers (modctl, KitOps), a CSI driver, and registry integrations — but no `run`/`serve`. A generic "Ollama alternative" would drown; *"the runtime companion to modctl: air-gapped, daemonless llama.cpp serving for ModelPack artifacts"* targets a real, underserved audience (platform/SRE teams in restricted environments) and is a strong portfolio piece at the Kubernetes/MLOps intersection. Risks: Ollama could ship first-class custom registries any quarter and erase the differentiation partially (not the standards-compliance part); llama.cpp CLI churn creates maintenance load. Ship v0.1 publicly at M6, invest in README/positioning, and let adoption decide how much further to go.

---

## 5. Architecture overview

```
                        ┌─────────────────────────────────────────────┐
                        │  K3s cluster                                │
   push (CI / laptop)   │  ┌───────────────┐      ┌───────────────┐   │
  ┌──────────────┐      │  │  zot registry │──S3──│    MinIO      │   │
  │ moci pack    │─────▶│  │  (Deployment) │      │ (blob backend)│   │
  │ moci push    │ HTTPS│  └──────┬────────┘      └───────────────┘   │
  └──────────────┘  +OIDC        │ OCI Distribution API              │
                        └────────┼────────────────────────────────────┘
                                 │
        ┌────────────────────────┼─────────────────────────────┐
        │                        │                             │
┌───────▼────────┐      ┌────────▼─────────┐         ┌─────────▼─────────┐
│ Workstation    │      │ K8s Pod          │         │ Air-gap transfer  │
│ (GPU)          │      │  initContainer:  │         │  moci save → tar  │
│ moci pull      │      │   moci pull      │         │  (sneakernet)     │
│ moci serve ────┼─▶ OpenAI API :11500     │         │  moci load        │
│  └ llama-server│      │  or image volume │         │  moci cp reg→reg  │
│    (managed)   │      │  (K8s ≥1.36)     │         └───────────────────┘
└────────────────┘      └──────────────────┘
```

Three planes:

1. **Registry plane** — zot backed by MinIO. Off-the-shelf. Section 6.
2. **Artifact plane** — ModelPack-format OCI artifacts wrapping GGUF + metadata. Section 7.
3. **Client plane** — the `moci` binary: transfer engine (oras-go), content-addressed local store, `llama-server` process manager, OpenAI router. Sections 8–9.

---

## 6. Registry layer (adopt, don't build)

**Primary choice: zot** (CNCF, single static Go binary, OCI-native). Reasons it fits this use case specifically:

- **S3 storage driver → MinIO** as backend; with `redirectBlobURL: true`, blob GETs return a 307 to a presigned MinIO URL, so multi-GB GGUF downloads stream straight from MinIO instead of proxying through zot. This is the single most important performance knob for model-sized blobs.
- **OIDC**: OpenID login for humans (dex/authentik/any issuer), plus **OIDC workload identity** bearer tokens so K8s pods and CI can pull with no static credentials, mapped to repo-level access-control policies.
- **Sync/mirroring** extension: an internet-facing zot can mirror selected repos, then be synced into the air-gapped zot (or use `moci cp` / `oras cp` / `skopeo` for sneakernet).
- Native OCI referrers → cosign signatures live next to the model; GC, retention policies, UI, Prometheus metrics built in.

**Alternatives** (document as ADR-002): `distribution` (registry:2) + S3 driver — simplest, no UI/OIDC/sync; **Harbor** — heavier, brings RBAC/scanning/replication, worth it only if it's wanted for container images anyway. All three speak the same protocol, so the client is unaffected; nothing in `moci` may depend on zot-specific behavior.

Deployment: Helm/ArgoCD app on K3s, TLS from the internal CA, `storageDriver: s3` pointed at MinIO with a dedicated bucket + access key (managed with the usual secrets tooling). Repo naming convention: `llm/<family>` for language models, `htr/<name>` for handwriting-recognition models, `runtimes/<name>` for llama-server builds.

```jsonc
// zot config sketch (trimmed)
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "/var/lib/zot",
    "storageDriver": {
      "name": "s3", "region": "main",
      "regionendpoint": "https://minio.internal:9000",
      "bucket": "zot-models", "secure": true
    },
    "redirectBlobURL": true,
    "gc": true, "dedupe": true
  },
  "http": {
    "address": "0.0.0.0", "port": "5000",
    "tls": { "cert": "...", "key": "..." },
    "auth": { "openid": { "providers": { "oidc": { "issuer": "https://sso.internal", "credentialsFile": "..." } } } }
  },
  "extensions": { "search": {"enable": true}, "ui": {"enable": true}, "sync": { "...": "..." } }
}
```

---

## 7. Artifact format

### 7.1 Alignment: ModelPack

Adopt the CNCF ModelPack spec (`modelpack/model-spec`) verbatim rather than defining `vnd.moci.*` types. Two reference implementations (modctl, KitOps) already exist, Harbor/Dragonfly/CRI-O understand it, and anything `moci` pushes must be pullable by `oras` and inspectable by generic tooling. Custom needs go in **annotations**, never new media types.

### 7.2 Manifest — "artifact" profile (primary)

One GGUF file per weight layer, stored **raw and uncompressed** (`.v1.raw`): GGUF is high-entropy, compression wastes CPU for ~0 gain, and raw layers mean the blob in the local store *is* the file `llama-server` mmaps — no unpack step, no double storage.

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.cncf.model.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.cncf.model.config.v1+json",
    "digest": "sha256:…", "size": 812
  },
  "layers": [
    {
      "mediaType": "application/vnd.cncf.model.weight.v1.raw",
      "digest": "sha256:…", "size": 4683074816,
      "annotations": { "org.cncf.model.filepath": "qwen3-8b-instruct-q4_k_m.gguf" }
    },
    {
      "mediaType": "application/vnd.cncf.model.weight.config.v1.raw",
      "digest": "sha256:…", "size": 1912,
      "annotations": { "org.cncf.model.filepath": "chat_template.jinja" }
    },
    {
      "mediaType": "application/vnd.cncf.model.doc.v1.raw",
      "digest": "sha256:…", "size": 11240,
      "annotations": { "org.cncf.model.filepath": "LICENSE" }
    }
  ],
  "annotations": {
    "org.opencontainers.image.source": "https://huggingface.co/Qwen/…",
    "org.opencontainers.image.licenses": "Apache-2.0",
    "io.moci.origin.sha256": "<sha256 of the original upstream file>",
    "io.moci.serve.defaults": "{\"ctx\":8192,\"ngl\":99}"
  }
}
```

Config blob (`vnd.cncf.model.config.v1+json`) carries structured metadata per the spec (family, parameter count, quantization, context length, format=gguf, architecture). Clients fetch this tiny JSON to answer `moci ls --remote` and "will it fit in VRAM?" questions without touching weights.

Multimodal models add the mmproj file as an extra `weight.v1.raw` layer; LoRA adapters can ship as their own artifacts referencing the base by digest annotation (stretch).

### 7.3 "Car" profile (secondary, for image volumes)

Kubernetes image volumes (GA in 1.36) mount OCI *objects* via the container runtime. CRI-O handles raw-layer artifacts; **containerd (what K3s ships) is only guaranteed for tar-layer images** (containerd ≥ 2.1). So `moci pack --profile car` additionally produces a modelcar-style OCI *image* — same GGUF inside a single tar layer, `vnd.oci.image.config.v1+json` config — tagged `<tag>-car`. Same content, two envelopes; the flywheel stays: artifact profile for `moci`/ORAS clients, car profile for kubelet/KServe consumption. (Test containerd artifact-mount behavior at M5; if K3s's containerd mounts raw artifacts cleanly by then, the car profile becomes optional.)

### 7.4 Naming and determinism

`registry.internal/llm/<family>:<size>-<variant>-<quant>` → `llm/qwen3:8b-instruct-q4_k_m`, plus immutable digest pins for GitOps (`@sha256:…` in K8s manifests, tags for humans). Packing is reproducible: fixed layer ordering, no timestamps in config, so re-packing identical inputs yields an identical digest.

---

## 8. Client CLI

### 8.1 Command surface

| Command | Behavior |
|---|---|
| `moci pull REF` | Resolve manifest, fetch missing blobs concurrently (resume via HTTP Range), verify digests, index locally |
| `moci push REF` | Push local model; skips blobs the registry has (cross-repo mount when supported) |
| `moci pack PATH…` | Build a ModelPack artifact from GGUF (+ template/license/mmproj); reads GGUF header to auto-fill config metadata; `--profile artifact\|car\|both`; `--push` |
| `moci ls` / `ls --remote REG` | Local store listing / registry catalog + config-blob metadata |
| `moci rm REF` | Unlink ref; `moci gc` reclaims unreferenced blobs |
| `moci run REF` | Ensure pulled, ensure runtime, spawn `llama-server`, open interactive chat (or `--web`) |
| `moci serve [REF…]` | The router: OpenAI endpoint on :11500, all/selected local models, lazy load + idle unload |
| `moci cp SRC DST` | Registry↔registry or registry↔`oci-layout` copy (air-gap workhorse) |
| `moci save/load` | Tarball of oci-layout for sneakernet |
| `moci sign/verify REF` | Cosign wrapper via sigstore-go; `verify` gate optionally enforced on pull |
| `moci login REG` | Basic/token/OIDC device flow; Docker-style credentials store |
| `moci runtime pull/ls` | Fetch pinned `llama-server` builds (cpu/cuda/metal) as OCI artifacts from `runtimes/` |

### 8.2 Local store

OCI image layout (the standard), shared content-addressed blobs:

```
~/.local/share/moci/
├── blobs/sha256/<digest>        # GGUF blobs land here once, shared across tags
├── index.json                    # oci-layout index: refs → manifests
├── runtimes/<name>/<version>/llama-server
└── state/                        # router runtime state, ports, pids
```

Because weight layers are raw, `llama-server -m ~/.local/share/moci/blobs/sha256/<digest>` works directly — zero-copy between "pulled" and "servable", identical to Ollama's trick but in a standard layout any OCI tool can read.

### 8.3 Transfer engine

Pending ADR-005, the preferred backend is **modctl's Go packages** for pack/pull/push (spec compliance and upstream alignment for free). Fallback: direct `oras-go` v2 (`oras.Copy` between `remote.Repository` and `oci.Store`), which provides resumable, concurrent, digest-verified transfers against any conformant registry, including auth (basic, token, OIDC bearer). Nothing registry-specific is implemented by hand. Progress UI via `mpb` or similar; `--concurrency` default 4 streams.

---

## 9. Serving layer

### 9.1 Runtime management

`moci` **manages, never embeds,** `llama-server`: a subprocess per loaded model, health-checked via `/health`, flags derived from `io.moci.serve.defaults` + model config + CLI overrides. Runtime binaries are version-pinned per `moci` minor release and distributed as OCI artifacts (`runtimes/llama-server:b<build>-cuda12`), which (a) solves air-gapped runtime delivery through the same pipe as models and (b) isolates llama.cpp's fast-moving flags behind one tested pin. cgo bindings are explicitly rejected (ADR-003): subprocess isolation means a llama.cpp crash doesn't kill the router, and upgrades are artifact swaps, not rebuilds.

### 9.2 Router (the UX heart)

`moci serve` exposes one OpenAI-compatible endpoint (`/v1/models`, `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`) on :11500 and routes by the request's `model` field:

- **Lazy load**: first request for a model spawns its `llama-server` on an ephemeral port, streams once ready.
- **Idle unload**: no requests for `--idle-timeout` (default 10 min) → SIGTERM, VRAM freed (DMR-style, tunable).
- **Resource guard**: single-flight loading with a VRAM budget check from the config blob's size metadata; on a 10 GB GPU, loading model B evicts model A (LRU) instead of OOMing the GPU.
- Streaming (SSE) is a transparent reverse proxy to the child; the router adds only routing, auth (optional bearer), and Prometheus metrics (`/metrics`: loads, evictions, TTFT, tokens/s) for any Prometheus-compatible stack.

Prior art acknowledged: this is llama-swap's concept, rebuilt natively so lifecycle and store are one system. LiteLLM keeps its place *in front* where it is already deployed; `moci serve` is just a better-behaved backend than hand-run `llama-server`.

---

## 10. Kubernetes integration

Three consumption patterns, least- to most-coupled:

1. **Init-container puller** (works everywhere today): a distroless `ghcr.io/…/moci` image; `moci pull $MODEL --output /models` into an emptyDir, main container runs any `llama-server` image against it. Auth via zot's OIDC workload identity → projected ServiceAccount token, no pull secrets.
2. **Image volumes** (K8s ≥ 1.36 GA, containerd ≥ 2.1 — verify the K3s channel at M5): mount the **car-profile** image directly:
   ```yaml
   volumes:
     - name: model
       image:
         reference: registry.internal/llm/qwen3:8b-instruct-q4_k_m-car
         pullPolicy: IfNotPresent
   ```
   Kubelet-managed caching/dedup on the node, no init container, digest-pinnable in Argo.
3. **KServe** `storageUri: oci://…` (modelcars) if/when KServe enters the picture.

Deliverables: Helm chart for the zot deployment, example manifests for patterns 1–2, and a short ADR on when to use which.

---

## 11. Security

- **Transport**: TLS everywhere from the internal CA; no `--insecure` code path shipped enabled by default (flag exists for lab bring-up, loudly warns).
- **AuthN/Z**: zot OIDC for humans (device flow in `moci login`), OIDC workload identity for pods/CI, repo-path policies (`llm/**` read-all, push restricted; `runtimes/**` push CI-only).
- **Integrity**: digest verification on every blob is inherent to OCI; `io.moci.origin.sha256` ties the artifact to the upstream file it was packed from.
- **Signing**: cosign keyless-or-key signatures as OCI referrers; `moci pull --verify` (and a `verify: required` config mode) refuses unsigned/foreign-signed models — models are attacker-controlled code-adjacent inputs, and the recent AUR supply-chain episode is exactly the threat model.
- **Licenses**: license file packed as a `doc` layer + SPDX annotation, so redistribution constraints travel with the weights.

---

## 12. Language and stack

On "the fastest language": the workload is **I/O-bound transfer + process supervision + HTTP proxying**; inference speed lives entirely in llama.cpp (C++/CUDA) regardless of the client language. Language choice is therefore about ecosystem leverage, and Go wins by a wide margin:

| Criterion | Go | Rust | Python |
|---|---|---|---|
| OCI libraries | **oras-go v2, go-containerregistry, containerd — canonical** | oci-client (thinner, less battle-tested) | oras-py (limited) |
| Distribution | Single static binary, trivial cross-compile | Same | Needs interpreter — disqualifying for daemonless goal |
| Reference peers | Ollama, zot, ORAS, kitops all Go — patterns to crib | — | RamaLama |
| Proxy/SSE perf | Ample (this is registry/K8s-component territory) | Ample | GIL-awkward |

**Decision: Go 1.24+** (ADR-004). Core deps: `modelpack/modctl` packages (pending ADR-005) and/or `oras-go/v2`, `spf13/cobra` + `viper`, `sigstore/sigstore-go`, `net/http` + `httputil.ReverseProxy` for the router, a small GGUF header reader (`gguf` key-value parsing is ~200 lines; avoids heavyweight deps), `prometheus/client_golang`. Rust would be a fine second choice if this were greenfield-everything, but rewriting oras-go's maturity is negative-value work here.

---

## 13. Repository layout, testing, CI

```
moci/
├── cmd/moci/                 # cobra entrypoints
├── internal/
│   ├── store/                # oci-layout local store, gc
│   ├── transfer/             # oras-go pull/push/cp, auth
│   ├── pack/                 # ModelPack builder, gguf header reader, car profile
│   ├── runtime/              # llama-server supervisor, runtime artifacts
│   ├── router/               # OpenAI endpoint, lifecycle, metrics
│   └── signing/
├── pkg/modelspec/            # ModelPack types (importable by others)
├── deploy/
│   ├── chart-zot/            # or upstream chart + values
│   └── k8s-examples/         # init-puller, image-volume, kserve
├── docs/adr/                 # ADR-001…, this design doc
└── .github/workflows/        # lint, test, e2e, goreleaser
```

**Testing strategy.** Unit tests around pack determinism (golden digests), GGUF header parsing, router state machine. **E2E in CI**: spin zot as a service container, pack + push + pull + `moci run --prompt` a tiny GGUF (SmolLM-135M-Q4 ≈ 90 MB or a stories-15M model ≈ 30 MB, vendored via HF in a cached CI step), assert an actual token comes back on CPU. Interop tests: artifact pushed by `moci` must pull cleanly with `oras` and `modctl`, and vice versa — this is the contract that keeps G2 honest. Release via goreleaser: linux/amd64, linux/arm64, darwin/arm64, plus the distroless puller image.

---

## 14. Milestones

Estimates in focused evenings/weekend-days (experienced Go-adjacent engineer; calendar time will vary).

| ID | Scope | Key deliverables | Acceptance criteria | Est. |
|---|---|---|---|---|
| **M0** | Spike + decision gate | zot on K3s (MinIO backend, TLS); manual `oras push/pull` of a GGUF; `llama-server` on the pulled blob; Ollama-vs-zot and RamaLama trials; ADR-001..004; name check | Gate decision recorded; end-to-end proven with zero custom code | 2–3 d |
| **M1** | Store + transfer | `pull`, `push`, `ls`, `rm`, `gc`, `login` — via modctl packages if ADR-005 confirms importability, else oras-go; oci-layout store; resume + concurrency | Pull a 5 GB model, interrupt, resume; blobs dedup across tags; `oras` can read the store's layout | 2–6 d (low end if modctl-backed) |
| **M2** | Pack + interop | `pack` (artifact profile) with GGUF autodetect; reproducible digests; interop tests vs `oras`/`modctl` | Same inputs → same digest; modctl pulls a moci-packed artifact intact | 3–4 d |
| **M3** | Run + serve (single) | `runtime pull` (llama-server as artifact); `run` interactive; `serve MODEL` single-model OpenAI endpoint | `curl /v1/chat/completions` streams from a pulled model on the GPU, CUDA runtime fetched from the registry | 4–6 d |
| **M4** | Router | Multi-model lazy load, idle unload, VRAM-budget LRU eviction, Prometheus metrics | Two models served on one port on 10 GB VRAM without OOM; Grafana panel shows loads/evictions | 5–7 d |
| **M5** | Air-gap + K8s | `cp`, `save/load`; car profile; init-puller image + manifests; image-volume validation on K3s (containerd version check); zot sync doc | Model moved offline via tarball and served; pod consumes model via both patterns | 4–6 d |
| **M6** | Security + release | `sign`/`verify` (cosign), `--verify` pull gate; OIDC login + workload identity docs; goreleaser, README/positioning, examples | v0.1.0 public: signed release binaries, quickstart works on a clean machine in <5 min | 4–6 d |
| *Stretch* | LoRA-adapter artifacts, mmproj/multimodal, embeddings models, HF import (`pack hf://…` online mode), llama-swap-style config file, safetensors/vLLM profile | — | — | — |

Total core: ~26–38 focused days. Sequencing note: M1+M3 already replace `llm-pull.py`/`llm-push.py` + hand-run `llama-server` — internal value lands early; M4–M6 are what make it publishable.

---

## 15. Risks and mitigations

| Risk | Likelihood | Impact | Mitigation |
|---|---|---|---|
| Ollama ships first-class custom registries, shrinking the niche | Medium | Medium | Differentiation also rests on ModelPack compliance + daemonless + router; M0 gate already prices this in |
| llama.cpp flag/API churn breaks `serve` | High | Medium | Runtime pinning per release; runtimes-as-artifacts make rollback a pull; CI e2e against the pinned build only |
| ModelPack spec evolves (it's CNCF sandbox) | Medium | Low | Types isolated in `pkg/modelspec`; interop tests vs modctl catch drift early |
| containerd artifact-mount semantics differ from CRI-O for image volumes | Medium | Low | Car profile is the hedge; validated at M5 on the actual K3s version |
| VRAM eviction heuristics wrong (metadata underestimates KV cache) | Medium | Medium | Conservative budget factor + measured RSS/VRAM feedback loop; manual `--keep-loaded` escape hatch |
| Scope creep toward vLLM/safetensors | High | Medium | Explicit non-goal until v0.1 ships; format already permits it later |
| Solo-maintainer fatigue post-publication | Medium | Low | Publish with clear "scope: GGUF + llama.cpp" statement; accept that "finished" is a valid state for a sharp tool |
| modctl `pkg/` API churn (pre-1.0 dependency) | Medium | Low | Pin versions; interop tests double as canaries; worst case fall back to oras-go (same plumbing underneath) |

---

## 16. Open questions

1. **Name** *(checked 2026-07)*: `moci` is muddy. The GitHub username `moci` is taken (no org possible at that path), npm `moci` is an active monorepo CLI installable via `npx moci@latest`, and several unrelated repos share the name (Met Office Coupling Infrastructure, an old Ruby CI service, an audio engine, an ML-paper codebase). None is dominant, and `github.com/<user>/moci` + `go install` work regardless — so: **acceptable as codename through M5, rename before the M6 public release** for searchability. Candidates to vet with the same rigor (unverified): `palan` (FR: hoist for heavy loads — on-metaphor), `gantry`, `gollem`.
2. Should `pull --verify` be default-on from v0.1 (stricter, better story) or opt-in (gentler adoption)?
3. Router port convention: 11500 chosen to avoid Ollama's 11434 — worth matching 11434 for drop-in client compat instead? (Con: confusing coexistence.)
4. Does the K3s channel in use ship containerd ≥ 2.1 with image-volume mount support, and does it accept raw-layer artifacts or only tar images? (Empirical answer at M5 decides the car profile's fate.)
5. HF online import (`pack hf://…`) — useful on the internet-facing side, dead weight in the air gap. Ship behind a build tag?
6. Upstream angle *(largely resolved in v0.2)*: transfer/pack belongs upstream in modctl (ADR-005); `moci` is the serving layer. Remaining sub-question: should the GGUF/raw-layer packing path itself land as a modctl PR rather than moci code? Decide during M2, informed by maintainer receptiveness on the community call.

---

## 17. References

- OCI Distribution Spec 1.1 / artifact guidelines — https://github.com/opencontainers/distribution-spec
- CNCF ModelPack spec (media types, annotations) — https://github.com/modelpack/model-spec · https://modelpack.org
- modctl — https://github.com/modelpack/modctl · KitOps — https://kitops.org
- zot (S3 driver, redirectBlobURL, OIDC, sync) — https://zotregistry.dev
- oras-go v2 — https://github.com/oras-project/oras-go
- RamaLama — https://github.com/containers/ramalama
- Docker Model Runner OCI artifact rationale — https://www.docker.com/blog/oci-artifacts-for-ai-model-packaging/
- Kubernetes image volumes (KEP-4639; GA v1.36) — https://kubernetes.io/docs/tasks/configure-pod-container/image-volumes/
- Ollama custom-registry state — ollama/ollama issues #2745, #7244, #4204, #9409
- llama-swap (router prior art) — https://github.com/mostlygeek/llama-swap
- llama.cpp server — https://github.com/ggml-org/llama.cpp
