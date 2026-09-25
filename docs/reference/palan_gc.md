## palan gc

Reclaim disk space from unreferenced blobs

### Synopsis

Gc reclaims blobs no tagged manifest refers to. An untagged artifact
that names a tagged one as its subject, such as one added with oras attach,
is kept with it. So is a model derived from a tagged base once its own tag
is removed, until nothing tagged reaches the base.

A signature left behind by a removed model is unlinked first. A signature
names its model as its subject, which keeps the model and all its weights
reachable, so an orphaned one would otherwise hold the whole model on disk.
Attestations and bills of materials go the same way.

Any other tagged artifact that names a subject is kept, such as a model
recording the base it was derived from, and so is the subject it names.

```
palan gc [flags]
```

### Examples

```
  # Reclaim what nothing refers to any more
  palan gc
```

### Options

```
  -h, --help   help for gc
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

