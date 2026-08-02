## palan load

Import models from a tar bundle

### Synopsis

load imports every tagged reference from a bundle created by save (or any tar'd OCI image layout). "-i -" reads from stdin.

With --verify, or with verify.required set in the config, every model in the
bundle must carry a valid signature before anything is imported. A bundle is
whatever a courier handed over, so this is the moment its provenance is worth
deciding. Verification reads the bundle itself and needs no registry.

```
palan load -i FILE [flags]
```

### Options

```
  -h, --help                help for load
  -i, --input string        input file (- for stdin)
      --verify              require a valid signature on every model in the bundle before importing
      --verify-key string   public key for --verify (default: verify.key from the config)
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

