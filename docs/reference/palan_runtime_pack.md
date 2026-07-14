## palan runtime pack

Pack a llama-server build as a runtime artifact

### Synopsis

Pack stores runtime files (the llama-server binary plus any shared
libraries) as an OCI artifact. The publisher-side counterpart of
'runtime pull'.

```
palan runtime pack PATH... -t REF --build BUILD [flags]
```

### Options

```
      --arch string         target architecture (GOARCH) (default "amd64")
      --build string        upstream build identifier, e.g. b4567 (required)
      --entrypoint string   executable file name among the packed files (default "llama-server")
      --flavor string       acceleration flavor: cpu|cuda12|metal|vulkan… (default "cpu")
  -h, --help                help for pack
      --name string         runtime name (default "llama-server")
      --os string           target OS (GOOS) (default "linux")
      --push                push to the registry after packing
  -t, --tag string          reference to tag the runtime with (required)
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

* [palan runtime](palan_runtime.md)	 - Manage inference runtimes distributed as OCI artifacts

