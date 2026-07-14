## palan pack

Build a ModelPack artifact from GGUF and companion files

### Synopsis

Pack reads the GGUF header to fill the model config (architecture,
quantization, size, context length) and stores a ModelPack artifact in the
local store under REF. Packing is reproducible: identical inputs yield an
identical digest.

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
      --ngl int                default GPU layer count for serving (io.palan.serve.defaults)
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

