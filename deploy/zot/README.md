# zot registry deployment (self-hosted reference)

zot is moci's reference registry (ADR-0002): CNCF, single binary, OCI-native,
S3 storage driver, OIDC, sync/mirroring, referrers support. moci itself works
against **any** OCI 1.1 registry — nothing here is required by the client.

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

1. **Secrets** (manage with your usual tooling — SOPS, sealed-secrets, …):
   - `zot-s3-credentials` with `access-key`/`secret-key` for a dedicated
     bucket (`zot-models`) on any S3-compatible store (MinIO, …).
   - `zot-oidc-credentials` with zot's `oidc-credentials.json`
     (`clientid`/`clientsecret` for your issuer).
2. **MinIO**: create the bucket; the `redirectBlobURL: true` knob makes blob
   GETs answer with a 307 to a presigned MinIO URL, so multi-GB GGUF pulls
   stream straight from MinIO instead of proxying through zot — the single
   most important performance setting for model-sized blobs (design §6).
3. **TLS**: terminate at the ingress with the internal CA, or configure
   `http.tls` in `config.json` with a mounted certificate. Clients that
   don't trust the internal CA system-wide can pass `--ca-file`.
4. **Access control**: the sketch in `values.yaml` gives anonymous read on
   `llm/**` and authenticated read elsewhere; pushes require named policies
   — tighten to your needs. For workload identity (pods pulling with
   projected ServiceAccount tokens, no static credentials), see zot's OIDC
   docs and pair with the init-puller example.

## Air-gap mirroring

Options, in increasing automation:

1. **Sneakernet**: `moci save llm/qwen3:8b-q4 -o bundle.tar` on the
   connected side; carry; `moci load -i bundle.tar && moci push …` inside.
2. **Direct copy** when a one-way path exists:
   `moci cp dmz.example/llm/qwen3:8b-q4 registry.internal/llm/qwen3:8b-q4`.
3. **zot sync**: give the internet-facing zot a `sync` extension config
   pulling selected repos, and let the internal zot sync from it on a
   schedule (`extensions.sync` in zot's config; content rules support
   per-repo filtering).

## Validation checklist (run on your cluster, not automatable from CI)

- [ ] `moci login registry.internal` (OIDC device flow or API key)
- [ ] `moci push registry.internal/llm/smoke:test` of a small packed model
- [ ] Pull from a pod using a projected SA token (no static secret)
- [ ] Blob GET redirects to object storage (curl -v shows the 307)
- [ ] zot `/metrics` scraped by your Prometheus-compatible stack
