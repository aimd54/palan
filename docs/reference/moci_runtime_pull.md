## moci runtime pull

Pull a runtime artifact and materialize its executable

```
moci runtime pull REF [flags]
```

### Options

```
  -h, --help   help for pull
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

* [moci runtime](moci_runtime.md)	 - Manage inference runtimes distributed as OCI artifacts

