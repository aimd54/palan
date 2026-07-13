## moci serve

Serve local models behind one OpenAI-compatible endpoint

### Synopsis

Serve exposes /v1/chat/completions, /v1/completions, /v1/embeddings, and
/v1/models for all local models (or only the given REFs) and routes by the
request's "model" field. Models load lazily on first use, unload after
--idle-timeout, and are evicted least-recently-used when the memory budget
fills up. Prometheus metrics are on /metrics.

```
moci serve [REF...] [flags]
```

### Options

```
      --addr string             listen address (default ":11500")
  -h, --help                    help for serve
      --idle-timeout duration   unload models idle longer than this (default 10m0s)
      --keep-loaded strings     refs never unloaded or evicted
      --memory-budget string    memory budget for loaded models, e.g. 9GiB (default: auto-detect)
      --runtime string          runtime artifact reference (default: runtime.ref config, then PATH)
```

### Options inherited from parent commands

```
      --ca-file string             PEM CA bundle to trust in addition to the system pool
      --concurrency int            parallel blob streams for transfers (default 4)
      --config string              config file (default ~/.config/moci/config.yaml)
      --insecure-skip-tls-verify   skip TLS certificate verification (dangerous; lab bring-up only)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [moci](moci.md)	 - Distribute and serve GGUF models as OCI artifacts

