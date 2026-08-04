## palan runtime ls

List runtime artifacts in the local store

```
palan runtime ls [flags]
```

### Examples

```
  # Runtimes held locally, with their build identifiers
  palan runtime ls
```

### Options

```
  -h, --help   help for ls
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

* [palan runtime](palan_runtime.md)	 - Manage inference runtimes distributed as OCI artifacts

