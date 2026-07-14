## palan describe

Show a model's metadata, annotations, and layer digests

### Synopsis

Describe answers metadata questions without touching weights: it reads
only the manifest and the small ModelPack config blob. REF is resolved in
the local store first, then on its registry.

```
palan describe REF [flags]
```

### Options

```
  -h, --help   help for describe
      --json   output JSON
```

### Options inherited from parent commands

```
      --ca-file string             PEM CA bundle to trust in addition to the system pool
      --concurrency int            parallel blob streams for transfers (default 4)
      --config string              config file (default ~/.config/palan/config.yaml)
      --insecure-skip-tls-verify   skip TLS certificate verification (dangerous; lab bring-up only)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [palan](palan.md)	 - Distribute and serve GGUF models as OCI artifacts

