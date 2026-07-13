## moci login

Log in to a registry

### Synopsis

Login validates credentials against the registry and saves them in the
Docker credentials store (a configured credential helper, or
~/.docker/config.json otherwise).

```
moci login REGISTRY [flags]
```

### Options

```
  -h, --help              help for login
      --password-stdin    read the password from stdin
  -u, --username string   registry username
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

