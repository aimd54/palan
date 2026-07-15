# Roadmap

Status of palan's build-out milestones as of July 2026.

| Milestone | Scope | Status |
|---|---|---|
| M0 | Spike + decision gate | ☑ decided (ADR-0001/0005); hands-on tool trials recorded as deferred |
| M1 | Store + transfer (`pull/push/ls/rm/gc/login`, resume, dedup) | ☑ shipped, unit + e2e tested |
| M2 | Pack + interop (reproducible digests; `oras`/`modctl` round-trips) | ☑ shipped, interop in CI |
| M3 | Run + serve single model (`runtime pull`, `run`) | ☑ shipped (CPU-tested; GPU validation pending, below) |
| M4 | Router (lazy load, idle unload, LRU eviction, metrics) | ☑ shipped, eviction demonstrated under a constrained budget |
| M5 | Air gap + K8s (`cp`, `save/load`, car profile, manifests) | ☑ shipped; K3s image-volume validation pending (below) |
| M6 | Security + release (sign/verify, gate, goreleaser) | ☑ shipped; cosign interop proven both directions |

## Pending validation on real infrastructure

These cannot be validated from CI and carry checklists in the repo:

- zot with an S3 backend and OIDC on a real cluster
  ([deploy/zot/README.md](../deploy/zot/README.md))
- CUDA serving on a GPU host (runtime artifact with a cuda flavor;
  `palan runtime pack … --flavor cuda12`)
- K8s image volumes on a containerd-based cluster — decides whether the
  car profile stays
  ([deploy/k8s-examples/README.md](../deploy/k8s-examples/README.md))

## Planned / open

- OIDC device-flow `login` (basic/token + credential helpers work today).
- Keyless (Fulcio/Rekor) signing for connected environments.
- `verify.required` as the default once signing pipelines are
  ubiquitous.
- Referrers-API storage for signatures alongside the tag fallback.
- Upstreaming the GGUF packing path to modctl if welcome (see ADR-0005).
- Stretch goals: LoRA adapter artifacts, multimodal mmproj, HF import
  (`pack hf://…`), safetensors/vLLM profile.
