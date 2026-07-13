## moci cp

Copy a model between registries

### Synopsis

cp streams an artifact from one registry to another without touching the
local store — the mirroring workhorse for DMZ-to-air-gap promotion.

```
moci cp SRC DST [flags]
```

### Options

```
  -h, --help   help for cp
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

