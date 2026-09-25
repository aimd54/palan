## palan rm

Unlink model references from the local store

### Synopsis

rm removes references; blob content stays on disk until `palan gc` reclaims it.

A model's signature and attestation go with it unless the store still
holds the model: while another tag names it, while an index or other
tagged content holds it, or while the store keeps the model it was derived
from.

A signature, attestation or other description removed by its own
reference loses only that reference when another names it too. Otherwise
it is deleted together with every tagged description of it under every
name, and theirs in turn, such as an attestation over a signature, and
each is listed. The removal is refused while other content in the store
refers to any of them.

```
palan rm REF... [flags]
```

### Examples

```
  # Unlink a model, then reclaim its blobs
  palan rm llm/qwen3:8b-q4
  palan gc
```

### Options

```
  -h, --help   help for rm
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

