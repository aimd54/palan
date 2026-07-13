# Consuming models in Kubernetes

Three patterns, least- to most-coupled (design §10). Pick the first one that
fits your cluster:

| Pattern | Works on | Profile served | Pros | Cons |
|---|---|---|---|---|
| [Init-container puller](init-puller.yaml) | any Kubernetes | artifact | works everywhere today; moci handles auth/resume/verification | model copied into an emptyDir per pod |
| [Image volume](image-volume.yaml) | K8s ≥ 1.36 (GA), containerd ≥ 2.1 | car (`…-car` tag) | kubelet-managed caching and dedup per node; no init container; digest-pinnable in GitOps | needs a recent runtime; car profile only |
| [KServe modelcar](kserve.yaml) | KServe ≥ 0.12 | car | full serving platform (scaling, canary) | brings all of KServe |

**Rules of thumb**

- Starting out or on an older cluster → init-container puller.
- K3s/containerd new enough and models change rarely → image volumes;
  pin `@sha256:` digests in your GitOps repo.
- Already running KServe for other models → modelcars.

**Validation checklist for image volumes on K3s** (decides the car
profile's future, design §16.4 — run on the actual cluster):

- [ ] `k3s --version` and embedded containerd ≥ 2.1
- [ ] `kubectl apply -f image-volume.yaml` mounts and the file is visible
- [ ] Test whether a **raw artifact** (non-car tag) also mounts — if yes,
      the car profile can be retired in a future release

**Auth without static secrets**: zot accepts OIDC bearer tokens; give pods a
projected ServiceAccount token whose issuer zot trusts, and set
`MOCI_REGISTRY_…` env or a mounted config accordingly. Fallback: a pull
secret consumed as `~/.docker/config.json` (moci reads the Docker
credentials store).
