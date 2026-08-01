# Consuming models in Kubernetes

Three patterns, least- to most-coupled. See
[Kubernetes integration](../../docs/architecture.md#kubernetes-integration)
for the overview. Pick the first one that fits your cluster:

| Pattern | Works on | Profile served | Pros | Cons |
|---|---|---|---|---|
| [Init-container puller](init-puller.yaml) | any Kubernetes | artifact | works everywhere today; palan handles auth/resume/verification | model copied into an emptyDir per pod |
| [Image volume](image-volume.yaml) | K8s ≥ 1.36 (GA), containerd ≥ 2.1 | car (`...-car` tag) | kubelet-managed caching and dedup per node; no init container; digest-pinnable in GitOps | needs a recent runtime; car profile only |
| [KServe modelcar](kserve.yaml) | KServe ≥ 0.12 | car | full serving platform (scaling, canary) | brings all of KServe |

## Rules of thumb

- Starting out or on an older cluster → init-container puller.
- K3s/containerd new enough and models change rarely → image volumes;
  pin `@sha256:` digests in your GitOps repo.
- Already running KServe for other models → modelcars.

## Why image volumes need the car profile

A raw ModelPack artifact does not mount as an image volume. Tested on
Kubernetes 1.36.1 with containerd 2.3.1: the kubelet reports a successful
pull of the full artifact, and then mounts an empty directory. containerd
stores the blob but never unpacks it, because
`application/vnd.cncf.model.weight.v1.raw` is not a layer type any snapshotter
applies. `ctr -n k8s.io images check` shows `UNPACKED false` for the artifact
next to `true` for the car image.

No error appears at any layer. A workload pointed at a raw tag starts, mounts
nothing, and fails once the inference server cannot find its model file, which
is a long way from the cause. The `-car` tag exists for this reason.

**Validation checklist for image volumes on K3s** (run on the actual cluster,
since K3s embeds its own containerd):

- [ ] `k3s --version` and embedded containerd ≥ 2.1
- [ ] `kubectl apply -f image-volume.yaml` mounts and the file is visible
- [ ] After a containerd upgrade, retest the raw artifact by pointing the same
      manifest at the non-car tag. Check that the mount has contents rather
      than that the pod starts: an empty mount is the failure mode, and it
      starts fine

**Auth without static secrets**: zot accepts OIDC bearer tokens; give pods a
projected ServiceAccount token whose issuer zot trusts, and set
`PALAN_REGISTRY_...` env or a mounted config accordingly. Fallback: a pull
secret consumed as `~/.docker/config.json` (palan reads the Docker
credentials store).
