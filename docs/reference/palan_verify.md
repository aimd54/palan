## palan verify

Verify a model's signature against a public key

### Synopsis

Verify checks a model's signature against a public key, or against the
keyless identities a trust policy names.

A model already in the local store is verified from there, so verification
needs no registry, no transparency log, and no certificate authority. Anything
else is resolved on its registry. The output names the source, since a local
result describes the copy you hold rather than what the registry serves now.

The signature is looked for under its tag first, then among the referrers of
the model, so a signature written by an OCI 1.1 signing tool is checked even
though it carries no tag.

A keyless signature names its signer instead of naming a key. Where a policy
rule lists identities, verify reads the signature bundle that travels with
the model and holds it against the trusted root the rule pins. The
transparency log entry must carry an inclusion proof reaching a log root
that root's key has signed, and a timestamp that same key signed, since a
keyless certificate lives minutes and is checked against the moment the log
recorded the signature rather than the present. An entry carrying no signed
timestamp is refused. All of that material travels with the artifact, so
this too needs no network. The signer is reported, since it is the one thing
the result establishes that the configuration did not already state.

Where sign also wrote a statement of the model's sources, verify checks it
against the same key and against the model's own layers, and names what the
layers came from. A model with no such statement verifies exactly as it did
before: requiring one is a policy for something else to enforce, not a fact
this command asserts. A source attestation is checked against the key that
signed the model, so a model verified by a keyless signature has its
provenance reported as unchecked rather than checked.

```
palan verify REF --key FILE [flags]
```

### Examples

```
  # Verify against a registry, or from the local store when it holds the signature
  palan verify registry.internal/llm/qwen3:8b-q4 --key cosign.pub
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
      --no-color                   disable colour output (NO_COLOR is honoured too)
      --plain-http                 use HTTP instead of HTTPS for registries
      --quiet                      suppress progress output
      --registry string            default registry host applied to short references
```

### SEE ALSO

* [palan](palan.md)	 - Distribute and serve GGUF models as OCI artifacts

