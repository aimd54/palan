# Roadmap

Status of palan's build-out milestones as of August 2026.

Two scopes run at different widths, and the distinction decides where most
items below belong. **Distribution** covers packing, transfer, signing,
verification and air-gap handling, and is format-neutral: weight layers travel
raw and the media type names no format. **Serving** is GGUF through llama.cpp
and refuses anything else, for the reasons in
[ADR-0012](adr/0012-distribution-is-format-neutral.md).

| Milestone | Scope | Status |
|---|---|---|
| M0 | Spike + decision gate | ☑ decided (ADR-0001/0005); hands-on tool trials recorded as deferred |
| M1 | Store + transfer (`pull/push/ls/rm/gc/login`, resume, dedup) | ☑ shipped, unit + e2e tested |
| M2 | Pack + interop (reproducible digests; `oras`/`modctl` round-trips) | ☑ shipped, interop in CI |
| M3 | Run + serve single model (`runtime pull`, `run`) | ☑ shipped; a CUDA runtime artifact serves on a 12 GB NVIDIA host |
| M4 | Router (lazy load, idle unload, LRU eviction, metrics) | ☑ shipped; acceptance measured on GPU (below) |
| M5 | Air gap + K8s (`cp`, `save/load`, car profile, manifests) | ☑ shipped; image volumes exercised on containerd 2.3.1 and 2.3.2 |
| M6 | Security + release (sign/verify, gate, goreleaser) | ☑ shipped; cosign interop proven both directions |
| M7 | Format-neutral distribution (safetensors packing, serving scope stated) | ☑ shipped (ADR-0012); a published single-file model packs, a sharded one and the registry round trip are untested |

## Validated outside CI

None of this can be exercised from CI, so it was run against a real registry,
a Kubernetes cluster, and a GPU host:

- **Registry**: zot with an S3 object-storage backend, `redirectBlobURL`
  confirmed to answer a blob GET with a presigned URL that the client fetches
  directly. Note that only an unranged `GET` redirects; `HEAD` and ranged
  requests are served by zot itself whatever the setting says. Three values in
  [`deploy/zot/values.yaml`](../deploy/zot/values.yaml) prevented zot from
  starting at all and have been corrected.
- **GPU serving**: a CUDA `llama-server` packed as a runtime artifact, pushed,
  pulled, and served. Router overhead against a hand-run `llama-server` on the
  same build and model measured at roughly 2.5%.
- **Router acceptance**: LRU eviction under a constrained budget frees memory
  instead of overcommitting the device, idle unload returns VRAM to its
  starting baseline, and the automatic budget probe resolves to 90% of device
  memory.
- **Image volumes**: the car profile mounts on Kubernetes 1.36 with containerd
  2.3.1 and with the 2.3.2 build K3s embeds. A raw ModelPack artifact does not,
  and reports no error while failing, which is why the car profile remains
  necessary. A registry that redirects blobs to object storage needs an
  endpoint the nodes can resolve, since containerd follows the redirect from
  the host network namespace. See
  [`deploy/k8s-examples/README.md`](../deploy/k8s-examples/README.md).
- **Init-container puller**: end to end from a registry into an `emptyDir`,
  including with a GPU attached to the serving container.
- **Air gap**: `save`/`load` bundles and registry-to-registry `cp`. Signatures
  travel with the model on all three paths, and a bundle verifies on a host
  with no network at all.
- **Verification policy**: `verify.required` is enforced by `pull`, `load`,
  `run`, and `serve`, so a model is checked both on its way into the store and
  each time it is loaded to be served.
- **Upstream import**: `pack hf://org/repo/file.gguf` fetches from Hugging
  Face, checks the bytes against the digest the repository publishes, and
  records it as the artifact's origin (ADR-0009).
- **Signature discovery**: a signed model is indexed by the registry's
  referrers API as well as tagged, and a signature written by an OCI 1.1
  signing tool, which carries no tag, verifies. Both checked against zot and
  the cosign binary (ADR-0010).

## Still outstanding

- **A safetensors model that arrives already sharded.** A published single-file
  model packs correctly, and the shard-index comparison has been exercised
  against real bytes by writing a legitimate one-shard index from a model's own
  header. What no run has used is an index naming several files, since the
  smallest published sharded model is around 5 GB.
- **A safetensors artifact through a registry.** Packing has been run against a
  published model. Push, pull into a fresh store with a digest comparison, and
  sign then verify have so far only run against synthetic shards in CI.
- zot on a cluster with OIDC rather than htpasswd. `/metrics` answers correctly
  for a listed user and refuses everyone else, but has not been scraped by a
  Prometheus-compatible collector ([deploy/zot/README.md](../deploy/zot/README.md)).
- A registry whose object storage sits on a different network from the cluster,
  which is where the blob redirect is most likely to break.
- KServe modelcars, the third Kubernetes consumption pattern.
- Router acceptance with two models large enough that the memory budget has to
  arbitrate between them, rather than a forced small budget.
- TLS end to end, which needs a certificate issuer the cluster trusts.

## Planned / open

- **`pack hf://` fetches a single file.** A safetensors model is published as a
  directory, so it comes down with another tool first and is packed from disk.
  Resolving a whole repository through the same path is the obvious next step
  for the import route (ADR-0009 covers the single-file case).
- **`precision` is recorded and not shown.** A safetensors model's dtype goes
  into the model config's `precision` field, since `quantization` names a scheme
  such as awq or gptq rather than a numeric type. Neither `ls`, `describe` nor
  their JSON output reads that field yet, so the value is currently invisible.
- **`/v1/models` lists references that cannot be served.** A safetensors
  artifact appears in the listing and is then refused on use, as an unsigned
  model already is under the verification policy. Filtering the listing to what
  a request would actually be served would spare a client the round trip.
- OIDC device-flow `login` (basic/token + credential helpers work today).
- Keyless (Fulcio/Rekor) signing for connected environments.
- `verify.required` as the default once signing pipelines are ubiquitous.
- Upstreaming the packing path to modctl if welcome (see ADR-0005).
- Stretch goals: LoRA adapter artifacts, multimodal mmproj.

## Decided against

- **Serving safetensors.** llama.cpp does not read them, and vLLM is a Python
  process carrying CUDA and torch, so it cannot travel as a static binary or
  start without a container runtime. Serving it would cost the property that
  lets palan run as an init container and on hosts with no container engine.
  For those weights palan is the distribution and verification layer in front of
  whichever inference stack is already running
  ([ADR-0012](adr/0012-distribution-is-format-neutral.md)).
