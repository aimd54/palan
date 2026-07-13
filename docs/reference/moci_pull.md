## moci pull

Pull a model from a registry into the local store

### Synopsis

Pull resolves REF on its registry and fetches missing blobs concurrently,
verifying digests. Interrupted downloads resume from where they stopped,
including across process restarts.

With --output, the model's files are additionally materialized into a
directory (named per their org.cncf.model.filepath annotations) — the
Kubernetes init-container pattern: pull into an emptyDir, serve with any
llama-server image.

```
moci pull REF [flags]
```

### Options

```
  -h, --help                help for pull
  -o, --output string       also materialize the model files into this directory
      --verify              verify the artifact's signature before downloading (always on when verify.required is set)
      --verify-key string   public key for --verify (default: verify.key from the config)
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

