# Architecture

palan treats GGUF models the way `docker`/`podman` treat images: `pull`,
`push`, `ls`, `run`, and `serve` against any standard OCI registry, then
serves them locally through llama.cpp's `llama-server` behind an
OpenAI-compatible endpoint.

palan is the client and serving layer only. Registries come from the
existing OCI ecosystem: zot, distribution, and Harbor are all self-hostable
and already provide content addressing, deduplication, resumable transfers,
auth, and replication for multi-gigabyte artifacts. The artifact format is
the CNCF [ModelPack](https://modelpack.org) specification
(`application/vnd.cncf.model.*` media types), which keeps artifacts legible
to the rest of that ecosystem.

## Overview

```text
 push (CI / laptop)
┌─────────────────┐   ┌──────────────────────────────────────────────────┐
│ palan pack      │   │ Kubernetes cluster                               │
│ palan push      │──▶│  ┌──────────────────┐      ┌──────────────────┐  │
└─────────────────┘   │  │ zot registry     │──S3──│ object store     │  │
  HTTPS + OIDC        │  │ (Deployment)     │      │ (blob backend)   │  │
                      │  └────────┬─────────┘      └──────────────────┘  │
                      │  OCI Distribution API                            │
                      └───────────┼──────────────────────────────────────┘
                                  │
          ┌───────────────────────┼───────────────────────┐
          │                       │                       │
┌─────────▼──────────┐  ┌─────────▼──────────┐  ┌─────────▼──────────┐
│ Workstation        │  │ K8s Pod            │  │ Offline transfer   │
│  palan pull        │  │  initContainer,    │  │  palan save → tar  │
│  palan serve       │  │  or image volume   │  │  palan load        │
│   ├ llama-server   │  │  (K8s ≥ 1.36)      │  │  palan cp reg→reg  │
│   └ OpenAI :11500  │  │                    │  │                    │
└────────────────────┘  └────────────────────┘  └────────────────────┘
```

Three planes make up the system:

1. **Registry plane**: any OCI 1.1 registry; zot is the reference
   deployment. See [Registry layer](#registry-layer).
2. **Artifact plane**: ModelPack-format OCI artifacts wrapping GGUF weights
   and metadata. See [Artifact format](#artifact-format).
3. **Client plane**: the `palan` binary, holding the transfer engine,
   content-addressed local store, `llama-server` process manager, and
   OpenAI-compatible router. See
   [Client and local store](#client-and-local-store) and
   [Serving layer](#serving-layer).

Every command is daemonless, with no background service to install,
configure, or keep alive. Two environments benefit most: disconnected
workstations, and thin Kubernetes init containers, where a container engine
or a persistent client-side daemon would itself be a barrier.

## Registry layer

palan speaks only the OCI Distribution Spec, so no part of the client
depends on registry-specific behavior. Any conformant registry works: zot,
Harbor, `distribution`, GHCR, ECR, and so on.

[zot](https://zotregistry.dev) is the reference deployment (see
[ADR-0002](adr/0002-zot-as-primary-registry.md) for the full rationale and
[`deploy/zot/`](../deploy/zot/README.md) for a working configuration): it's
a single static Go binary, OCI-native, with an S3 storage driver, OIDC
authentication for both humans and workloads, a sync/mirroring extension,
and native OCI referrers so cosign signatures live next to the model they
sign.

```jsonc
// zot config sketch (trimmed)
{
  "distSpecVersion": "1.1.1",
  "storage": {
    "rootDirectory": "/var/lib/zot",
    "storageDriver": {
      "name": "s3", "region": "us-east-1",
      "regionendpoint": "https://s3.internal:9000",
      "bucket": "zot-models", "secure": true
    },
    "redirectBlobURL": true,
    "gc": true, "dedupe": true
  },
  "http": {
    "address": "0.0.0.0", "port": "5000",
    "tls": { "cert": "...", "key": "..." },
    "auth": { "openid": { "providers": { "oidc": { "issuer": "https://sso.example.com", "credentialsFile": "..." } } } }
  },
  "extensions": { "search": {"enable": true}, "ui": {"enable": true}, "sync": { "...": "..." } }
}
```

With `redirectBlobURL: true`, blob GETs return a redirect to a presigned URL
on the object store instead of proxying the bytes through zot. For
model-sized blobs this is the single most important performance knob.

## Artifact format

### ModelPack alignment

palan adopts the CNCF ModelPack spec verbatim. Reference implementations
already exist (`modctl`, KitOps), Harbor, Dragonfly, and CRI-O understand
the format natively, and anything palan pushes stays pullable by `oras` and
inspectable by generic OCI tooling. palan-specific needs go in
**annotations**, never in new media types.

### Manifest: the "artifact" profile

Each GGUF file is stored as its own weight layer, **raw and
uncompressed**: GGUF is already high-entropy, so compression wastes CPU for
close to zero size gain, and a raw layer means the blob in the local store
*is* the file `llama-server` mmaps, with no unpack step and no double
storage.

```json
{
  "schemaVersion": 2,
  "mediaType": "application/vnd.oci.image.manifest.v1+json",
  "artifactType": "application/vnd.cncf.model.manifest.v1+json",
  "config": {
    "mediaType": "application/vnd.cncf.model.config.v1+json",
    "digest": "sha256:...", "size": 812
  },
  "layers": [
    {
      "mediaType": "application/vnd.cncf.model.weight.v1.raw",
      "digest": "sha256:...", "size": 4683074816,
      "annotations": { "org.cncf.model.filepath": "qwen3-8b-instruct-q4_k_m.gguf" }
    },
    {
      "mediaType": "application/vnd.cncf.model.weight.config.v1.raw",
      "digest": "sha256:...", "size": 1912,
      "annotations": { "org.cncf.model.filepath": "chat_template.jinja" }
    },
    {
      "mediaType": "application/vnd.cncf.model.doc.v1.raw",
      "digest": "sha256:...", "size": 11240,
      "annotations": { "org.cncf.model.filepath": "LICENSE" }
    }
  ],
  "annotations": {
    "org.opencontainers.image.source": "https://huggingface.co/Qwen/...",
    "org.opencontainers.image.licenses": "Apache-2.0",
    "io.palan.origin.sha256": "<sha256 of the original upstream file>",
    "io.palan.serve.defaults": "{\"ctx\":8192,\"ngl\":99}"
  }
}
```

The config blob (`vnd.cncf.model.config.v1+json`) carries structured
metadata per the spec: family, parameter count, quantization, context
length, format, and architecture. Clients fetch this small JSON document to
answer `palan ls --remote` or `palan describe` questions, and to check
whether a model will fit in VRAM, without touching any weight bytes. See
`palan describe` in the [CLI reference](reference/palan_describe.md).

### "Car" profile for image volumes

Kubernetes image volumes mount OCI *objects* directly via the container
runtime. Not every runtime supports raw-layer artifacts for this yet, so
`palan pack --profile car` additionally produces a modelcar-style OCI
*image*: the same GGUF wrapped in a single tar layer with a standard image
config, tagged `<tag>-car`. Same content, two envelopes. The artifact
profile serves palan and ORAS clients, the car profile serves kubelet and
KServe. See the [Kubernetes guide](guides/kubernetes.md) for when to use
which.

### Naming and determinism

References follow `registry/llm/<family>:<size>-<variant>-<quant>`, e.g.
`llm/qwen3:8b-instruct-q4_k_m`, with immutable digest pins available for
GitOps (`@sha256:...` in manifests, tags for humans). Packing is
reproducible: layer ordering is fixed and no timestamps land in the config,
so re-packing identical inputs yields an identical digest every time.

## Client and local store

The local store is a standard OCI image layout with shared,
content-addressed blobs:

```text
~/.local/share/palan/
├── blobs/sha256/<digest>        # GGUF blobs land here once, shared across tags
├── index.json                   # oci-layout index: refs → manifests
├── runtimes/<name>/<version>/llama-server
└── state/                       # router runtime state, ports, pids
```

Because weight layers are stored raw, `llama-server -m
~/.local/share/palan/blobs/sha256/<digest>` works directly; "pulled" and
"servable" are the same state. The layout itself stays readable by any
OCI-aware tool.

Transfers go through [oras-go v2](https://github.com/oras-project/oras-go):
resumable (via HTTP Range requests, including across process restarts),
concurrent, and digest-verified against any conformant registry, with
support for basic, token, and OIDC bearer authentication. See
[ADR-0005](adr/0005-transfer-backend-oras-go.md) for why oras-go was chosen
over building a transfer layer from scratch or depending on `modctl`.

## Serving layer

### Runtime management

palan manages `llama-server` as a subprocess: one process per loaded model,
health-checked, with flags derived from the model's
`io.palan.serve.defaults` annotation plus any CLI overrides. `llama-server`
builds are themselves version-pinned OCI artifacts
(`runtimes/llama-server:<build>-<flavor>`) distributed through the same
registries as the models, so runtime delivery uses the same pipe as model
delivery, offline included. Subprocess isolation also means a llama.cpp
crash never takes the router down with it; see
[ADR-0003](adr/0003-llama-server-as-subprocess.md).

### Router

`palan serve` exposes one OpenAI-compatible endpoint (`/v1/models`,
`/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`) and routes by
the request's `model` field:

- **Lazy load**: the first request for a model spawns its `llama-server`
  on an ephemeral port and streams once it's ready.
- **Idle unload**: a model with no requests for `--idle-timeout` (default
  configurable; see `palan serve --help`) is stopped and its memory freed.
- **Resource guard**: single-flight loading with a memory-budget check
  against the config blob's size metadata. Loading a model that would
  exceed the budget evicts the least-recently-used model.
- Streaming responses are a transparent reverse proxy to the child process;
  the router adds only routing, optional bearer auth, and Prometheus
  metrics (`/metrics`: loads, evictions, time-to-first-token, tokens/s).

## Kubernetes integration

Three consumption patterns, from least- to most-coupled. The
[Kubernetes guide](guides/kubernetes.md) has manifests and tradeoffs:

1. **Init-container puller**: a distroless palan image runs `palan pull
   $MODEL --output /models` into an `emptyDir`; the main container runs any
   `llama-server` image against it.
2. **Image volumes**: on clusters that support it, the car-profile image
   mounts directly as a volume, kubelet-managed and digest-pinnable.
3. **KServe**: `storageUri: oci://...` against the car-profile image
   (modelcars).

## Security model

- Every blob transfer is digest-verified end to end; a corrupted or
  tampered blob is discarded, never installed.
- Cosign signatures are stored under cosign's tag convention,
  `sha256-<manifest digest>.sig`, in the model's own repository, and travel
  with the model through `pull`, `save`, and `cp`. Verification reads either a
  registry or the local store, so it needs no transparency log, no certificate
  authority, and no network once the signature is on disk.
- `verify.required` (or `--verify` on a single command) refuses unsigned or
  foreign-signed models at every point one could get in or get used: `pull`
  before any weight bytes move, `load` against the bundle before anything
  reaches the store, `run` before deciding to fetch, and `serve` each time a
  model is loaded. The last one is what covers a store changed after import,
  since the others only see content on its way in.

See the [Security guide](guides/security.md) for signing workflows,
authentication, and TLS configuration, and
[ADR-0001](adr/0001-build-on-oci-and-modelpack.md) for how building on OCI
and ModelPack supplies most of this integrity story.
