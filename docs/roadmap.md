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
| M7 | Format-neutral distribution (safetensors packing, serving scope stated) | ☑ shipped (ADR-0012); exercised against a published model, single-file and sharded, through a registry and an air gap |
| M8 | Import provenance (whole `hf://` repositories, publisher digests and signatures) | ☑ shipped; whole repositories resolve from the shard index, and a publisher signature is checked against every file when a key is supplied |
| M9 | Pack attestation (upstream files bound to layers, carried as a referrer) | ☑ shipped (ADR-0014); the statement survives a registry-to-bundle-to-store round trip and verifies offline, and cosign reads what palan writes |
| M10 | Trust policy (which identities may sign which references) | ☑ shipped; enforced at the same four points as `verify.required`, each checked to leave the store or the served spec untouched on a refusal, with a companion rule set naming the key a source must be signed with at import |
| M11 | Keyless verification from carried material (no network, no log) | ☑ shipped (ADR-0015); a signature carrying its certificate and inclusion proof verifies against a pinned root with the registry gone, and is refused once that proof is stripped |
| M12 | Verification surface (`verify --explain`, gate patterns, load-time re-hash) | ☐ planned |
| M13 | 1.0 (verification on by default, stable policy format) | ☐ planned |

M8 through M13 build out one property end to end: that the bytes a host
loads are the bytes a publisher released and an identity approved, checkable
on any host, connected or not. Signing and verification exist today (M6);
M8 adds the stretch before signing, checking a publisher's own digests and,
when a key is supplied, their signature as well; M9 makes that stretch
portable, stating in a signed form which upstream file each layer holds so
the claim survives leaving the machine that packed it; M10 puts a policy
above the single key, naming which identities may sign which references
rather than trusting one key for everything a registry holds, and names
per source the publisher key an import must be held against. What remains
is the carried material that lets verification hold with no network, and
the surfaces that show and enforce the result, described under
[Planned milestones](#planned-milestones). Work that waits on infrastructure
rather than on code sits outside that sequence, under
[Ecosystem validations](#ecosystem-validations).

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
- **Source attestation**: a model packed from a repository, signed, pushed,
  pulled, carried through a bundle into a store that was never pointed at the
  registry, and verified there, with the output naming the repository and the
  commit the listing resolved to. `cosign verify-attestation` accepts the same
  statement, which is what holds the format claim to the tool rather than to
  its documentation (ADR-0014).
- **Signature discovery**: a signed model is indexed by the registry's
  referrers API as well as tagged, and a signature written by an OCI 1.1
  signing tool, which carries no tag, verifies. Both checked against zot and
  the cosign binary (ADR-0010).
- **A redirect the client cannot follow**: with object storage on a network the
  client cannot reach, a pull fails while the registry answers healthily, since
  the client and not the registry follows the redirect. Reproduced with two
  container networks, and the message names both the registry it asked and the
  redirect target it could not reach. The same pull from the storage-side
  network succeeds. Note that `redirectBlobURL` belongs beside `storageDriver`
  rather than inside it: nested one level deeper it is ignored without an error.
- **Transport security**: against a private certificate authority, palan
  verifies the chain and refuses an untrusted certificate rather than
  continuing, and `--ca-file` is what makes a private authority usable.
- **Metrics collection**: `/metrics` is scraped by a Prometheus-compatible
  collector, which records the series rather than only receiving a 200.
- **Safetensors, end to end**: a published model packed, pushed, pulled into a
  store that had never seen it with the digest unchanged, signed, verified,
  carried through an air gap and verified again with the registry deleted. Run
  both as a single file and as three shards named by an index, where naming one
  shard packs the whole model. The weight layer's digest equals the checksum of
  the file the publisher released, so nothing rewrites the weights in transit.
  Serving refuses these artifacts by name (ADR-0012).

## Planned milestones

In dependency order. Each lands the way the shipped ones did: with tests
that were seen to fail before the change, and validations recorded above
once they run against real infrastructure.

### M12: the chain, shown and enforced

- `verify --explain`, plain text and `--json`: origin, attestation,
  signature identity, and every hop it can prove, so "prove what is on this
  host" becomes one command's output. For an artifact palan did not produce
  it says plainly which links it cannot prove.
- The gate pattern, documented and measured: an init container that refuses
  on the policy so the serving container never starts, with example
  manifests for a plain Deployment whose runtime reads safetensors, and for
  KServe. A refusal must leave the shared volume empty and must be prompt
  rather than a hang.
- An opt-in re-hash of weight blobs at load, closing the gap ADR-0008
  deferred: a substituted blob behind an intact manifest refuses. Opt-in,
  because it re-reads gigabytes.
- The runtime channel gains the same gate, so an engine build is checked the
  way a model is when it is installed or spawned.

### M13: 1.0

`verify.required` becomes the default, with a first-run path that does not
strand a store predating signing. The policy file format is documented as
stable, and a transfer benchmark against modctl and oras is published with
its methodology. The README's claims are then re-read against what ships,
since 1.0 is a statement about defaults as much as about features.

## Ecosystem validations

Independent of the milestones and of each other, and none of them gates
1.0. Each is a validation with a recorded result rather than a feature, and
each waits on infrastructure rather than on code: a cluster, an identity
provider, an ACME issuer, a mirror. They run as that infrastructure comes
within reach.

- KServe modelcars, the third Kubernetes consumption pattern. Raw deployment
  mode suffices, which avoids pulling in a service mesh, so a laptop cluster
  reaches it ([deploy/k8s-examples/](../deploy/k8s-examples/README.md)).
- zot behind OIDC rather than htpasswd, with palan carrying a token obtained
  from the provider; an identity provider in a container is enough.
- A publicly trusted certificate, once an ACME issuer exists to test
  against. The client half is done: palan verifies a chain and refuses an
  untrusted one, tested against a private CA.
- A pull through a Dragonfly mirror, validated once and documented.
- A palan bundle inside a Zarf package, so a workload and its models cross
  an air gap together.
- Offering the packing path and the origin and attestation conventions
  upstream to modctl if welcome (ADR-0005's standing plan), and a CNCF
  landscape entry.

## Alongside the milestones

- **Two models large enough that the memory budget has to arbitrate between
  them**, rather than a budget set deliberately small. Waits on a GPU with
  enough memory for both, and on the models being present. Eviction, idle
  unload and the automatic budget probe are all measured; what is untested is
  the arithmetic when a wrong estimate would surface as an allocation failure
  instead of an eviction.
- **`precision` is recorded and not shown.** A safetensors model's dtype goes
  into the model config's `precision` field, since `quantization` names a scheme
  such as awq or gptq rather than a numeric type. Neither `ls`, `describe` nor
  their JSON output reads that field yet, so the value is currently invisible.
- **`/v1/models` lists references that cannot be served.** A safetensors
  artifact appears in the listing and is then refused on use, as an unsigned
  model already is under the verification policy. Filtering the listing to what
  a request would actually be served would spare a client the round trip.

## Deferred

- OIDC device-flow `login` (basic/token + credential helpers work today).
- Keyless (Fulcio/Rekor) signing for connected environments; M11 covers the
  verification half.
- Stretch goals: LoRA adapter artifacts, multimodal mmproj.

## Decided against

- **Serving safetensors.** llama.cpp does not read them, and vLLM is a Python
  process carrying CUDA and torch, so it cannot travel as a static binary or
  start without a container runtime. Serving it would cost the property that
  lets palan run as an init container and on hosts with no container engine.
  For those weights palan is the distribution and verification layer in front of
  whichever inference stack is already running
  ([ADR-0012](adr/0012-distribution-is-format-neutral.md)).
- **A Kubernetes operator.** palan appears in a cluster as an init container
  and as artifacts. Controllers, custom resources and admission webhooks
  belong to the platforms that already run them, and a second control plane
  would cost the property that palan needs no daemon anywhere.
- **Transport acceleration beyond resume and concurrency.** Peer-to-peer
  distribution and cache hierarchies are what registry mirrors and Dragonfly
  are for; palan pulls through them rather than reimplementing them.
- **A model scanner.** The store is a plain OCI layout precisely so existing
  scanners and OCI tooling can read it.
