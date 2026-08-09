## palan pack

Build a ModelPack artifact from GGUF or safetensors weights

### Synopsis

Pack reads the weights to fill the model config (architecture,
quantization, size, context length) and stores a ModelPack artifact in the
local store under REF. Packing is reproducible: identical inputs yield an
identical digest.

A model split across parts (model-00001-of-00003.gguf) is packed whole:
naming any part brings its siblings in from the same directory, and a part
that is missing is an error, since one part alone would pack and describe
itself like a complete model and then fail to load.

A safetensors model is published as a directory, so naming the directory
packs it. The shard index (model.safetensors.index.json) states which shards
the model is made of: all of them are packed, along with config.json and any
tokenizer files beside them, and a shard the index names that the directory
does not hold is an error. Naming one shard packs the same set.

That artifact is for distribution and verification. It pushes, pulls, signs,
verifies and travels through an air gap on the same code path a GGUF one
does; serve and run refuse it, because llama.cpp reads GGUF and the artifact
declares what it holds. --license is the only source of a license for it,
since safetensors publishes none, and --ctx and --ngl describe llama.cpp's
command line, so they carry no meaning on it.

A PATH may be a local file or a Hugging Face source,
hf://<org>/<repo>/<file>, which is downloaded first:

  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4

The bytes are checked against the SHA-256 the repository publishes and
refused if they differ, that digest becomes io.palan.origin.sha256, and the
repository page becomes the source annotation. Split parts and a licence
file in the repository travel with the weights. Naming a repository without
a file lists what it publishes. Gated repositories read HF_TOKEN.

Profiles: "artifact" (raw weight layers; the default), "car" (an OCI image
with one tar layer under models/, for Kubernetes image volumes and KServe
modelcars; tagged REF-car), or "both".

```
palan pack PATH... -t REF [flags]
```

### Examples

```
  # Pack a local GGUF with its licence and serving defaults
  palan pack qwen3-8b-q4.gguf LICENSE -t llm/qwen3:8b-q4 --ctx 8192 --ngl 99

  # Pack a safetensors model directory for distribution
  palan pack ./Qwen3-8B/ -t llm/qwen3:8b-safetensors --license Apache-2.0

  # Pack straight from Hugging Face, then push
  palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf -t llm/qwen3:8b-q4 --push
```

### Options

```
      --ctx int                default context size for serving (io.palan.serve.defaults)
  -h, --help                   help for pack
      --license string         SPDX license expression (default: the GGUF header's general.license; safetensors publishes none)
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
      --no-color                   disable colour output (NO_COLOR is honoured too)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [palan](palan.md)	 - Distribute and serve GGUF models as OCI artifacts

