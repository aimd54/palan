## palan pack

Build a ModelPack artifact from GGUF and companion files

### Synopsis

Pack reads the GGUF header to fill the model config (architecture,
quantization, size, context length) and stores a ModelPack artifact in the
local store under REF. Packing is reproducible: identical inputs yield an
identical digest.

A PATH may be a local file or a Hugging Face source,
hf://<org>/<repo>/<file>, which is downloaded first:

  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4

The bytes are checked against the SHA-256 the repository publishes and
refused if they differ, that digest becomes io.palan.origin.sha256, and the
repository page becomes the source annotation. A split GGUF brings every
sibling part, and a licence file in the repository travels with the weights.
Naming a repository without a file lists what it publishes. Gated
repositories read HF_TOKEN.

Profiles: "artifact" (raw GGUF layers; the default), "car" (an OCI image
with one tar layer under models/, for Kubernetes image volumes and KServe
modelcars; tagged REF-car), or "both".

```
palan pack PATH... -t REF [flags]
```

### Options

```
      --ctx int                default context size for serving (io.palan.serve.defaults)
  -h, --help                   help for pack
      --license string         SPDX license expression (default: the GGUF header's general.license)
      --ngl int                default GPU layer count for serving; unset means serve passes no --n-gpu-layers (io.palan.serve.defaults)
      --origin-sha256 string   SHA-256 of the original upstream file (default: the weight digest)
      --profile string         output profile: artifact|car|both (default "artifact")
      --push                   push to the registry after packing
      --source string          upstream source URL (org.opencontainers.image.source)
  -t, --tag string             reference to tag the packed model with (required)
```

### Options inherited from parent commands

```
      --ca-file string             PEM CA bundle to trust in addition to the system pool
      --concurrency int            parallel blob streams for transfers (default 4)
      --config string              config file (default ~/.config/palan/config.yaml)
      --insecure-skip-tls-verify   skip TLS certificate verification (dangerous; lab bring-up only)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [palan](palan.md)	 - Distribute and serve GGUF models as OCI artifacts

