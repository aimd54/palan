## moci ls

List models in the local store or a remote registry

```
moci ls [flags]
```

### Options

```
  -h, --help            help for ls
      --json            output JSON
      --remote string   list a remote registry (host[:port]) instead of the local store
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

