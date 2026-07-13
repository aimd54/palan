## moci push

Push a locally-stored model to its registry

### Synopsis

Push uploads the model tagged REF in the local store to its registry.
Blobs the registry already has are skipped, and where supported, blobs known
from sibling repositories are mounted server-side instead of re-uploaded.

```
moci push REF [flags]
```

### Options

```
  -h, --help   help for push
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

