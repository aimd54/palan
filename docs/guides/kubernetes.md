# Serving palan-packed models on Kubernetes

Ready-to-adapt manifests live in
[`deploy/k8s-examples/`](../../deploy/k8s-examples/README.md); this guide
explains the moving parts.

## Which pattern?

1. **Init-container puller** — works on any cluster, today. A distroless
   palan image runs `palan pull REF --output /models` into an `emptyDir`;
   the main container is any llama-server image pointed at the file.
   palan brings digest verification, resume, and (later) signature
   verification to the pull; the serving image needs no registry logic.

2. **Image volumes** (Kubernetes ≥ 1.36, containerd ≥ 2.1) — the kubelet
   mounts the **car-profile** image (`REF-car`) directly:

   ```yaml
   volumes:
     - name: model
       image:
         reference: registry.internal/llm/qwen3:8b-instruct-q4_k_m-car
         pullPolicy: IfNotPresent
   ```

   Node-level caching and dedup come from the container runtime; pin
   `@sha256:` digests in GitOps. The car profile exists because containerd
   guarantees mounting only for tar-layer *images*, not raw artifacts (see
   ["Car" profile](../architecture.md#artifact-format)) — CRI-O mounts raw
   artifacts natively.

3. **KServe modelcars** — `storageUri: oci://…-car` if KServe is already in
   the picture.

## Registry authentication for pods

Preferred: **no static credentials**. zot accepts OIDC bearer tokens, so a
projected ServiceAccount token (with zot configured to trust the cluster
issuer) lets pods pull with their workload identity. Fallback: a standard
image pull secret mounted as the Docker config — palan reads the Docker
credentials store.

## GPU nodes

The examples are CPU-shaped. On GPU nodes add the device resource and an
accelerated llama-server image (or a palan runtime artifact with a CUDA
flavor):

```yaml
resources:
  limits:
    nvidia.com/gpu: 1
```

Validation of image volumes on your cluster's containerd — and whether raw
artifacts mount without the car profile — is a per-environment checklist
item; see the [examples README](../../deploy/k8s-examples/README.md).
