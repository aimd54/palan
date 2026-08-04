## palan runtime pull

Pull a runtime artifact and materialize its executable

```
palan runtime pull REF [flags]
```

### Examples

```
  # Fetch a llama-server build and unpack it ready to run
  palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12
```

### Options

```
  -h, --help   help for pull
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

