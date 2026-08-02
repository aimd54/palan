# Roadmap

Status of palan's build-out milestones as of August 2026.

| Milestone | Scope | Status |
|---|---|---|
| M0 | Spike + decision gate | ☑ decided (ADR-0001/0005); hands-on tool trials recorded as deferred |
| M1 | Store + transfer (`pull/push/ls/rm/gc/login`, resume, dedup) | ☑ shipped, unit + e2e tested |
| M2 | Pack + interop (reproducible digests; `oras`/`modctl` round-trips) | ☑ shipped, interop in CI |
| M3 | Run + serve single model (`runtime pull`, `run`) | ☑ shipped; a CUDA runtime artifact serves on a 12 GB NVIDIA host |
| M4 | Router (lazy load, idle unload, LRU eviction, metrics) | ☑ shipped; acceptance measured on GPU (below) |
| M5 | Air gap + K8s (`cp`, `save/load`, car profile, manifests) | ☑ shipped; image volumes exercised on containerd 2.3.1 |
| M6 | Security + release (sign/verify, gate, goreleaser) | ☑ shipped; cosign interop proven both directions |

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
  2.3.1. A raw ModelPack artifact does not, and reports no error while failing,
  which is why the car profile remains necessary. See
  [`deploy/k8s-examples/README.md`](../deploy/k8s-examples/README.md).
- **Init-container puller**: end to end from a registry into an `emptyDir`,
  including with a GPU attached to the serving container.
- **Air gap**: `save`/`load` bundles and registry-to-registry `cp`. Signatures
  travel with the model on all three paths, and a bundle verifies on a host
  with no network at all.

## Still outstanding

- zot on a cluster with OIDC rather than htpasswd, and `/metrics` scraped by a
  Prometheus-compatible collector
  ([deploy/zot/README.md](../deploy/zot/README.md)).
- Image volumes on K3s, which embeds its own containerd build. The result
  above is strong evidence rather than proof for that runtime.
- KServe modelcars, the third Kubernetes consumption pattern.

## Planned / open

- Enforcing `verify.required` in `run` and `serve`. It is honoured by `pull`
  and by `load`, so content is checked as it enters the store, but nothing
  re-checks a model at the moment it is served.
- Referrers-API storage for signatures alongside the tag fallback.
- OIDC device-flow `login` (basic/token + credential helpers work today).
- Keyless (Fulcio/Rekor) signing for connected environments.
- `verify.required` as the default once signing pipelines are ubiquitous.
- Upstreaming the GGUF packing path to modctl if welcome (see ADR-0005).
- Stretch goals: LoRA adapter artifacts, multimodal mmproj, HF import
  (`pack hf://...`), safetensors/vLLM profile.
