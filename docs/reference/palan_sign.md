## palan sign

Sign a pushed model with a cosign-compatible key

### Synopsis

Sign resolves REF on its registry and attaches a cosign-compatible
signature next to it (the sha256-<digest>.sig tag convention), so
'cosign verify --key' and 'palan verify' both accept it. The signature also
names the model as its subject, so the registry indexes it through the
referrers API and tools that look there find it too.

The signature then travels with the model through pull, save, and cp, and
verifying it needs no transparency log, no certificate authority, and no
registry once it is in the local store. Encrypted cosign keys are supported;
the password comes from COSIGN_PASSWORD or an interactive prompt.

Where the layers record where their files were fetched from, sign also
writes a source attestation: a signed statement, stored the same two ways
as the signature, binding each layer to the upstream file it holds. An
artifact packed purely from local disk has no upstream to name, and sign
says so rather than leaving the absence unremarked.

```
palan sign REF --key FILE [flags]
```

### Examples

```
  # Sign after pushing; the signature lands beside the model
  palan push registry.internal/llm/qwen3:8b-q4
  palan sign registry.internal/llm/qwen3:8b-q4 --key cosign.key
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
      --config string              config file (default ~/.config/palan/config.yaml)
      --insecure-skip-tls-verify   skip TLS certificate verification (dangerous; lab bring-up only)
      --no-color                   disable colour output (NO_COLOR is honoured too)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [palan](palan.md)	 - Distribute and serve GGUF models as OCI artifacts

