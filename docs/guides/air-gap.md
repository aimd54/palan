# Air-gapped model distribution with palan

Models and the llama-server runtimes that serve them move through the same
channel: standard OCI registries, or offline bundles where there is no
network path at all. Every transfer is digest-verified end to end.

## The two sides

- **Connected side**: a machine that can reach upstream sources
  (Hugging Face, ghcr.io) and the connected-side registry.
- **Air-gapped side**: the internal registry (e.g. zot, see
  [`deploy/zot/`](../../deploy/zot/README.md)) and the workstations/cluster
  that pull from it.

## 1. Package on the connected side

```sh
# Model: GGUF + chat template + license, with provenance annotations
palan pack qwen3-8b-instruct-q4_k_m.gguf chat_template.jinja LICENSE \
  -t connected.example/llm/qwen3:8b-instruct-q4_k_m \
  --source https://huggingface.co/Qwen/... \
  --ctx 8192 --ngl 99 \
  --profile both --push

# Runtime: a pinned llama-server build (from llama.cpp releases).
# Include the compute backends, which live beside the binary or under ggml/.
palan runtime pack llama-server lib*.so ggml/*.so \
  -t connected.example/runtimes/llama-server:b4567-cuda12 \
  --build b4567 --flavor cuda12 --push
```

Pack every shared library the runtime needs, not only the ones it is obvious
about. The offline host may have no llama.cpp installed at all, and a binary
that finds the host's copies on the connected side has nothing to fall back on
in the gap. palan points the dynamic loader at the unpacked runtime directory,
so packed libraries are used even when the executable carries no `$ORIGIN`
runpath.

`ldd` is not a sufficient inventory. It reports link-time libraries, while
llama.cpp's compute backends are opened with `dlopen` at startup and never
appear there. Depending on the build they sit beside the binary or in their own
directory, such as `ggml/` next to the libraries. Pack those files too: a
runtime assembled from `ldd` output alone arrives with no backend at all.

Backends also fail quietly. A backend whose own dependencies are missing is
skipped without an error, leaving the runtime to fall back on whatever else it
can load, so a build meant for a GPU can end up serving on the CPU or on an
unrelated accelerator. Ask the runtime what it found rather than trusting the
pack step:

```sh
llama-server --list-devices
```

Libraries built against a newer C library than the target host still fail
there, which is worth checking before the transfer rather than after.

Packing is reproducible: identical inputs give identical digests, so
re-packing on both sides of the gap yields verifiable equality.

## 2. Cross the gap

Pick per your topology:

### Physical transfer (no network path at all)

```sh
# Connected side: one bundle can carry several refs, blobs deduplicated
palan pull connected.example/llm/qwen3:8b-instruct-q4_k_m
palan save connected.example/llm/qwen3:8b-instruct-q4_k_m \
          connected.example/runtimes/llama-server:b4567-cuda12 \
          -o transfer.tar
# ... carry transfer.tar across ...
# Air-gapped side:
palan load -i transfer.tar
palan push registry.internal/llm/qwen3:8b-instruct-q4_k_m   # after re-tagging, see note
```

The bundle is a tar of a standard OCI image layout, inspectable with
`oras`, `tar tf`, or any OCI tool. Note: refs keep their original registry
host inside the bundle; re-tag on import side with a pull/push pair or use
`palan cp` when a one-way path exists.

### One-way network path (connected side → offline side)

```sh
palan cp connected.example/llm/qwen3:8b-instruct-q4_k_m \
        registry.internal/llm/qwen3:8b-instruct-q4_k_m
```

**Continuous mirroring**: zot's `sync` extension pulls selected repos from
the connected-side zot on a schedule; see the registry runbook.

## 3. Serve inside

```sh
palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12
palan pull registry.internal/llm/qwen3:8b-instruct-q4_k_m
palan serve --keep-loaded registry.internal/llm/qwen3:8b-instruct-q4_k_m
# → OpenAI-compatible endpoint on :11500, metrics on /metrics
```

Interrupted pulls resume where they stopped, including across reboots,
via HTTP Range requests against the registry.

## Integrity and provenance across the gap

- Every blob transfer is digest-verified; a bundle tampered in transit
  fails on load/pull.
- `io.palan.origin.sha256` ties the artifact to the upstream file it was
  packed from; `org.opencontainers.image.source` records where.
- Cosign signatures travel with the artifact and verify inside the gap.
  Signatures use cosign's tag convention, `sha256-<manifest digest>.sig` in the
  same repository. `palan pull` brings a model's signature down beside it,
  `palan save` writes it into the bundle, and `palan cp` copies it to the
  destination registry, so nothing has to be named or fetched separately.
- Verification reads whichever source holds the answer. A model whose
  signature is in the local store is verified from there, needing no registry,
  no transparency log, and no certificate authority. `palan verify` names the
  source it used, since a local result describes the copy you hold rather than
  what a registry serves now.
- Check a bundle on the way in rather than after trusting it:

  ```sh
  palan load -i qwen3.tar --verify --verify-key cosign.pub
  ```

  With `verify.required` in the config this happens without the flag. Either
  way the check runs against the bundle before any content reaches the store,
  so a bundle that fails to verify imports nothing.

- A signature binds the repository reference it was created for. The in-gap
  registry must serve the model under the same reference, otherwise
  verification fails on identity even though the key and digest match. See the
  [security guide](security.md) for signing workflows.
