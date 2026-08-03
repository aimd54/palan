## palan verify

Verify a model's signature against a public key

### Synopsis

Verify checks a model's signature against a public key.

A model already in the local store is verified from there, so verification
needs no registry, no transparency log, and no certificate authority. Anything
else is resolved on its registry. The output names the source, since a local
result describes the copy you hold rather than what the registry serves now.

The signature is looked for under its tag first, then among the referrers of
the model, so a signature written by an OCI 1.1 signing tool is checked even
though it carries no tag.

```
palan verify REF --key FILE [flags]
```

### Options

```
  -h, --help         help for verify
      --key string   public key file (cosign.pub; default: verify.key from the config)
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

