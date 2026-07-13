## moci runtime

Manage inference runtimes distributed as OCI artifacts

### Synopsis

Runtimes are version-pinned llama-server builds distributed through the
same registries as the models (conventionally under runtimes/), so air-gapped
hosts receive inference engines through the already-established channel.

### Options

```
  -h, --help   help for runtime
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
* [moci runtime ls](moci_runtime_ls.md)	 - List runtime artifacts in the local store
* [moci runtime pack](moci_runtime_pack.md)	 - Pack a llama-server build as a runtime artifact
* [moci runtime pull](moci_runtime_pull.md)	 - Pull a runtime artifact and materialize its executable

