## moci sign

Sign a pushed model with a cosign-compatible key

### Synopsis

Sign resolves REF on its registry and attaches a cosign-compatible
signature next to it (the sha256-<digest>.sig tag convention), so
'cosign verify --key' and 'moci verify' both accept it — including fully
offline. Encrypted cosign keys are supported; the password comes from
COSIGN_PASSWORD or an interactive prompt.

```
moci sign REF --key FILE [flags]
```

### Options

```
  -h, --help         help for sign
      --key string   private key file (cosign.key or PEM; required)
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

