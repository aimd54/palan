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

Each weight file is stored as its own weight layer, **raw and
uncompressed**: weight data is already high-entropy, so compression wastes
CPU for close to zero size gain, and a raw layer means the blob in the local
store *is* the file `llama-server` mmaps, with no unpack step and no double
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

### Weight formats

The weight media type, `application/vnd.cncf.model.weight.v1.raw`, is
format-agnostic: a layer under it holds whatever bytes the publisher
released, a GGUF file or one shard of a safetensors model. The config blob's
`format` field is what distinguishes them. It reads `gguf` or `safetensors`,
and it surfaces in the `FORMAT` column of `palan ls` and in
`palan describe`.

Everything between `pack` and the weights landing on a node addresses layers
by digest and media type. Push, pull, signing, verification, garbage
collection, offline bundles and the car profile read no weight file at all,
so they behave identically on either format. Serving is where the two part
company: `llama-server` reads GGUF, so `palan serve` and `palan run` load a
GGUF artifact and refuse one whose config declares another format, naming
that format in the refusal. A safetensors artifact is distributed and
verified here and served by a runtime that reads it, vLLM being the usual
one. See [ADR-0012](adr/0012-distribution-is-format-neutral.md).

A safetensors model is packed from its directory, since that is the shape a
repository publishes it in. The shard index
(`model.safetensors.index.json`) states which shards the model consists of;
all of them are packed, together with `config.json` and any tokenizer files
beside them, and a set the index says is short is refused. What each format
publishes decides what the artifact can record: a GGUF header states
quantization, context length and a license, while a safetensors repository
states architecture and context length in `config.json`, publishes a dtype
that lands in the config's `precision` field, and leaves `--license` as the
only source of a license.

A repository can also be named directly, `hf://<org>/<repo>` with no file,
which packs from Hugging Face rather than disk. The same shard index decides
which weights belong to the model: a repository publishing a second
quantization or an adapter beside the indexed shards keeps it out of the
artifact, and an index naming a shard the repository does not publish is
refused rather than packed short.

A repository publishes a digest for its LFS-stored files; a small file
served inline, such as `config.json`, publishes none. Each layer built
from a fetched file that carried a published digest records it, in bare
hex, as `io.palan.origin.sha256` at the layer's own scope; a file with no
published digest is packed with that annotation absent rather than
invented. The manifest-scope annotation of the same name keeps its
existing meaning when a single file was named: the `sha256:`-prefixed
upstream digest of that file. Naming a bare repository leaves nothing to
prefer there, so it falls back instead to the packed weight layer's own
digest, in bare hex.

### Source attestation

An annotation records where a layer came from; it does not, on its own, make
that a checkable claim. A layer built from a fetched file also records
`io.palan.source.repo`, `io.palan.source.path` and `io.palan.source.revision`,
written only where a value exists, so an artifact packed from local files is
unchanged.

`palan sign` turns those annotations into a signed statement: an in-toto
Statement in a DSSE envelope, predicate type `https://palan.dev/source/v1`,
listing for each layer its own digest, the repository, the path, the commit,
and the digest that repository published. It is stored the way a signature
is, under cosign's `sha256-<manifest digest>.att` tag and named as a referrer
of the model, and cosign reads it. A layer whose source is not fully known
contributes nothing, and a statement covering no layers is not written at
all: one that verifies while vouching for nothing would read as a checked
chain.

`palan verify` reads the statement back and holds every layer it names
against the artifact's own manifest, so it cannot vouch for a layer the
artifact does not contain. The statement travels with the model through
`pull`, `save` and `cp`, each of which reports whether it did (ADR-0014).

### "Car" profile for image volumes

Kubernetes image volumes mount OCI *objects* directly via the container
runtime. Not every runtime supports raw-layer artifacts for this yet, so
`palan pack --profile car` additionally produces a modelcar-style OCI
*image*: the same files wrapped in a single tar layer with a standard image
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
- Importing from a Hugging Face repository checks the same way at the
  boundary before anything is packed: a file the repository publishes a
  digest for, which is every file it stores as LFS, is held against that
  digest and refused on mismatch; a small file served inline carries none
  to check and is packed with its origin unrecorded. Given
  `pack --oms-key`, the repository's own signature over the files it
  publishes, in the OpenSSF model-signing format, is verified as well, and
  every downloaded file is checked against what it covers, including a
  file with no published digest of its own; a file the signature omits, or
  one whose bytes hash differently, refuses the import. The verifying key
  is recorded as `io.palan.origin.signer`.
- Cosign signatures are stored under cosign's tag convention,
  `sha256-<manifest digest>.sig`, in the model's own repository, and travel
  with the model through `pull`, `save`, and `cp`. Verification reads either a
  registry or the local store, so it needs no transparency log, no certificate
  authority, and no network once the signature is on disk.
- The signature also names the model as its **subject**, so registries index it
  through the referrers API and a signed model is visible to tooling that
  discovers artifacts that way rather than by constructing the tag. The tag
  remains what `cosign verify --key` reads. Verification tries the tag first and
  falls back to referrers, which is how a signature written by an OCI 1.1
  signing tool, carrying no tag at all, is checked
  ([ADR-0010](adr/0010-referrers-alongside-the-signature-tag.md)).
- Signing a model packed from a repository also writes a **source
  attestation**, a signed statement binding each layer to the upstream file
  it holds, stored and discovered the same two ways as the signature.
  Verification reads it back and refuses one that names a layer the artifact
  does not contain. What it proves is that these layers hold the files that
  repository served under those digests; the commit it records is the one the
  repository reported, so it is a claim about palan's handling rather than
  about the source's honesty
  ([ADR-0014](adr/0014-source-attestation-binds-layers-to-upstream-files.md)).
- `verify.required` (or `--verify` on a single command) refuses unsigned or
  foreign-signed models at every point one could get in or get used: `pull`
  before any weight bytes move, `load` against the bundle before anything
  reaches the store, `run` before deciding to fetch, and `serve` each time a
  model is loaded. The last one is what covers a store changed after import,
  since the others only see content on its way in.
- `verify.policy` decides *which* identity may sign *which* reference, where
  `verify.key` trusts one key for everything. Rules pair a pattern over
  `registry/repository` with the keys allowed to sign what it matches, the
  first match decides, and a reference no rule names is refused. A
  companion `verify.sources` names the key a source repository must have
  signed its own published digests with, so an import is checked because the
  host is configured rather than because an operator remembered a flag.

See the [Security guide](guides/security.md) for signing workflows,
authentication, and TLS configuration, and
[ADR-0001](adr/0001-build-on-oci-and-modelpack.md) for how building on OCI
and ModelPack supplies most of this integrity story.
