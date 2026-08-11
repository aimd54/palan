# zot registry deployment (self-hosted reference)

zot is palan's reference registry (ADR-0002): CNCF, single binary, OCI-native,
S3 storage driver, OIDC, sync/mirroring, referrers support. palan itself works
against **any** OCI 1.1 registry; nothing here is required by the client.

## Install

```sh
helm repo add project-zot https://project-zot.github.io/helm-charts
helm repo update
# Review the chart's values against ours first:
helm show values project-zot/zot | less
helm install zot project-zot/zot -n registry --create-namespace \
  -f values.yaml
```

For GitOps, wrap the same chart + values in an Argo CD `Application`.

## Before applying

1. **Secrets** (manage with your usual tooling: SOPS, sealed-secrets, ...):
   - `zot-s3-credentials` with `access-key`/`secret-key` for a dedicated
     bucket (`zot-models`) on your object store.
   - `zot-oidc-credentials` with zot's `oidc-credentials.json`
     (`clientid`/`clientsecret` for your issuer).
2. **Object storage**: create the bucket. The `redirectBlobURL: true` knob
   makes blob GETs answer with a 307 to a presigned URL, so multi-GB GGUF
   pulls stream straight from the object store instead of proxying through
   zot. This is the single most important performance setting for
   model-sized blobs (see
   [Registry layer](../../docs/architecture.md#registry-layer)).

   It belongs beside `storageDriver`, not inside it, as in
   [values.yaml](values.yaml). Nested one level deeper it is ignored: zot
   starts, serves blobs and logs nothing, and an unranged GET answers 200
   where it should answer 307. Check for the 307 rather than assume the
   setting took.

   Any store implementing the S3 API works, and zot's driver needs a small
   part of it: presigned URLs, signature v4, path-style addressing
   (`forcepathstyle`), ranged reads and multipart upload. Versioning, ACLs,
   object locking and replication are never used, so a store that omits them
   is fine. Garage, SeaweedFS and AWS S3 itself all satisfy this; the
   worked example below uses Garage because it is a single binary and
   self-hosts comfortably.
3. **TLS**: terminate at the ingress with the internal CA, or configure
   `http.tls` in `config.json` with a mounted certificate. Clients that
   don't trust the internal CA system-wide can pass `--ca-file`.
4. **Access control**: the sketch in `values.yaml` gives anonymous read on
   `llm/**` and authenticated read elsewhere; pushes require named policies.
   Tighten to your needs. For workload identity (pods pulling with
   projected ServiceAccount tokens, no static credentials), see zot's OIDC
   docs and pair with the init-puller example.

## Worked example: Garage as the object store

Create the bucket and a key scoped to it, then read the credentials back:

```sh
garage bucket create zot-models
garage key create zot-models-rw
garage bucket allow --read --write zot-models --key zot-models-rw
garage key info --show-secret zot-models-rw
```

Put those two values in the `zot-s3-credentials` Secret, then match
`values.yaml` to the deployment:

- `regionendpoint` to the address clients reach the store on, which includes
  nodes if image volumes are in use
- `region` to whatever the store advertises as its S3 region, which Garage
  sets in its own configuration rather than inferring
- `secure: false` only while bringing up a store without TLS
- `forcepathstyle: true` stays as it ships: path-style addressing needs no
  per-bucket DNS

A store on a different network segment from the cluster is the case worth
testing deliberately, because the client follows the redirect. See the
checklist below.

## Air-gap mirroring

Options, in increasing automation:

1. **Sneakernet**: `palan save llm/qwen3:8b-q4 -o bundle.tar` on the
   connected side; carry; `palan load -i bundle.tar && palan push ...` inside.
2. **Direct copy** when a one-way path exists:
   `palan cp dmz.example/llm/qwen3:8b-q4 registry.internal/llm/qwen3:8b-q4`.
3. **zot sync**: give the internet-facing zot a `sync` extension config
   pulling selected repos, and let the internal zot sync from it on a
   schedule (`extensions.sync` in zot's config; content rules support
   per-repo filtering).

## Validation checklist (run on your cluster, not automatable from CI)

- [ ] `palan login registry.internal -u <user> --password-stdin`, which stores
      the credential in the Docker credentials store. A device flow is on the
      roadmap rather than in the binary, so an interactive OIDC login is not
      available yet
- [ ] `palan push registry.internal/llm/smoke:test` of a small packed model
- [ ] Pull from a pod using a projected SA token (no static secret)
- [ ] Blob GET redirects to object storage (curl -v shows the 307). Use an
      unranged GET: zot serves HEAD and ranged requests itself, so they show
      no redirect regardless of `redirectBlobURL`
- [ ] The redirect target resolves from wherever clients run. The presigned
      URL carries the host named in `regionendpoint`, so a name that resolves
      only inside the cluster leaves external pulls failing against a registry
      that reports itself healthy. A node counts as such a client: containerd
      pulling an image volume resolves names in the host network namespace, so
      a `*.svc.cluster.local` endpoint fails there while pods succeed
- [ ] zot `/metrics` scraped by your Prometheus-compatible stack, with the
      scraper's username listed under `accessControl.metrics`
