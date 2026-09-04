## palan serve

Serve local models behind one OpenAI-compatible endpoint

### Synopsis

Serve exposes /v1/chat/completions, /v1/completions, /v1/embeddings, and
/v1/models for all local models (or only the given REFs) and routes by the
request's "model" field. Models load lazily on first use, unload after
--idle-timeout, and are evicted least-recently-used when the memory budget
fills up. Prometheus metrics are on /metrics.

GPU offload comes from the model, not from serve: --n-gpu-layers is passed
only when the model was packed with 'pack --ngl' (io.palan.serve.defaults).
Without it serve leaves the choice to the runtime, and a build that defaults
to no offload will serve from CPU on a GPU host.

```
palan serve [REF...] [flags]
```

### Examples

```
  # Serve every model in the store, loading each on first request
  palan serve

  # Keep one model resident and cap what may be loaded at once
  palan serve --keep-loaded llm/qwen3:8b-q4 --memory-budget 9GiB
```

### Options

```
      --addr string             listen address (default ":11500")
  -h, --help                    help for serve
      --idle-timeout duration   unload models idle longer than this (default 10m0s)
      --keep-loaded strings     refs never unloaded or evicted
      --memory-budget string    memory budget for loaded models, e.g. 9GiB (default: auto-detect)
      --rehash                  read each model's blobs back at load and hold them to the digests its manifest records
      --runtime string          runtime artifact reference (default: runtime.ref config, then PATH)
      --verify                  require a valid signature before loading any model
      --verify-key string       public key for --verify (default: verify.key from the config)
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

