## palan runtime pull

Pull a runtime artifact and materialize its executable

### Synopsis

Pull fetches a runtime artifact and unpacks its executable ready to run.

A runtime is an engine that will read the weights, so it is signed and
verified the way a model is. With --verify, or with verify.required set in
the config, the signature is checked on the registry before anything is
downloaded, and the trust policy decides who may sign it.

```
palan runtime pull REF [flags]
```

### Examples

```
  # Fetch a llama-server build and unpack it ready to run
  palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12

  # Refuse the build unless it carries a valid signature
  palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12 --verify
```

### Options

```
  -h, --help                help for pull
      --verify              require a valid signature on the runtime before downloading it
      --verify-key string   public key for --verify (default: verify.key from the config)
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

