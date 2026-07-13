## moci load

Import models from a tar bundle

### Synopsis

load imports every tagged reference from a bundle created by save (or any tar'd OCI image layout). "-i -" reads from stdin.

```
moci load -i FILE [flags]
```

### Options

```
  -h, --help           help for load
  -i, --input string   input file (- for stdin)
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

