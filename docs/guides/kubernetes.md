# Serving palan-packed models on Kubernetes

Ready-to-adapt manifests live in
[`deploy/k8s-examples/`](../../deploy/k8s-examples/README.md); this guide
explains the moving parts.

## Which pattern?

1. **Init-container puller**: works on any cluster, today. A distroless
   palan image runs `palan pull REF --output /models` into an `emptyDir`;
   the main container is any llama-server image pointed at the file.
   palan brings digest verification, resume, and signature verification to
   the pull; the serving image needs no registry logic.

2. **Image volumes** (Kubernetes ≥ 1.36, containerd ≥ 2.1): the kubelet
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
   ["Car" profile](../architecture.md#artifact-format)). CRI-O mounts raw
   artifacts natively.

3. **KServe modelcars**: `storageUri: oci://...-car` if KServe is already in
   the picture. The manifest ships in
   [`deploy/k8s-examples/kserve.yaml`](../../deploy/k8s-examples/kserve.yaml)
   and has not been run against a cluster, unlike the two patterns above.

## The gate: refusing before anything serves

The init-container puller becomes an enforcement point once a trust policy is
mounted beside it. The init container verifies before it writes, so a model no
rule admits never reaches the `emptyDir`, and Kubernetes never starts the
serving container: init containers run to completion in order, and a non-zero
exit holds the pod in `Init:Error`.

```yaml
initContainers:
  - name: verify-and-pull
    image: ghcr.io/aimd54/palan:latest
    args: [pull, registry.internal/llm/qwen3:8b-instruct, --output=/models, --config=/etc/palan/config.yaml]
```

The config the init container reads carries `verify.required` and the policy
rules; the public key comes from a Secret. Full manifests, for a plain
Deployment and for a KServe predictor, are in
[`gate-init.yaml`](../../deploy/k8s-examples/gate-init.yaml) and
[`gate-kserve.yaml`](../../deploy/k8s-examples/gate-kserve.yaml).

Two properties make this an enforcement point rather than a warning. A refusal
writes nothing, so the volume the serving container mounts stays empty, and it
returns rather than waiting: nothing palan does on this path reads standard
input, which in a pod would be a hang with no output rather than a failure.
Both are measured against a real registry in the e2e suite.

The serving container in those manifests is vLLM reading safetensors, which
palan distributes and does not serve
([ADR-0012](../adr/0012-distribution-is-format-neutral.md)). That is the
division the gate is for: palan decides whether the bytes are allowed onto the
host, and whatever is already running inference reads them. Swapping in a
llama.cpp image and a GGUF artifact changes nothing else.

## Registry authentication for pods

Preferred: **no static credentials**. zot accepts OIDC bearer tokens, so a
projected ServiceAccount token (with zot configured to trust the cluster
issuer) lets pods pull with their workload identity. Fallback: a standard
image pull secret mounted as the Docker config, which palan reads from the
Docker credentials store.

## GPU nodes

The examples are CPU-shaped. On GPU nodes add the device resource and an
accelerated llama-server image (or a palan runtime artifact with a CUDA
flavor):

```yaml
resources:
  limits:
    nvidia.com/gpu: 1
```

Validating image volumes against your cluster's containerd, and checking
whether raw artifacts mount without the car profile, is a per-environment
task; see the [examples README](../../deploy/k8s-examples/README.md).
