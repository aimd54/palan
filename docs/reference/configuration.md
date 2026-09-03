# Configuration reference

palan reads, in order of precedence (highest wins):

1. command-line flags
2. environment variables: `PALAN_` prefix, dots/dashes become underscores
   (e.g. `PALAN_REGISTRY_DEFAULT`, `PALAN_SERVE_BEARER_TOKEN`)
3. the config file: `--config PATH`, else `~/.config/palan/config.yaml`

The local store location is separate: `PALAN_HOME`, else
`$XDG_DATA_HOME/palan`, else `~/.local/share/palan`.

## Keys

```yaml
registry:
  default: registry.internal   # host applied to short refs like llm/qwen3:8b
  plain-http: false            # HTTP instead of HTTPS (lab bring-up)
  ca-file: ""                  # extra PEM CA bundle (internal CA)
  insecure-skip-tls-verify: false  # dangerous; warns loudly

transfer:
  concurrency: 4               # parallel blob streams

runtime:
  ref: ""                      # default runtime artifact for run/serve,
                               # e.g. registry.internal/runtimes/llama-server:b4567-cuda12
                               # (empty: llama-server from PATH)

serve:
  addr: ":11500"
  idle-timeout: 10m
  memory-budget: ""            # e.g. 9GiB; empty auto-detects (GPU VRAM, else RAM/2)
  bearer-token: ""             # require Authorization: Bearer ... when set

verify:
  required: false              # verify signatures on every pull
  key: ""                      # public key, when no policy names one per reference
  # policy:                    # rules of pattern + keys and/or identities; a set policy replaces key
  # sources:                   # rules of pattern + oms-key, for hf:// imports
```

Both list keys are absent by default, and neither accepts an empty list:
written as `policy: []` the load is refused, so a host that wants no policy
leaves the key out entirely.

`verify.policy` maps reference patterns to who may sign them, and once it
names any rule `verify.key` is no longer consulted. A rule names `keys`,
`identities`, or both:

```yaml
verify:
  policy:
    - pattern: registry.internal/llm/*
      keys:
        - /etc/palan/team.pub
    - pattern: registry.internal/vendor/**
      trust-root: /etc/palan/sigstore-root.json
      identities:
        - subject: https://github.com/vendor/models/.github/workflows/release.yml@refs/tags/*
          issuer: https://token.actions.githubusercontent.com
```

`keys` are public key files. `identities` are keyless signers, each a
`subject` matched with `*` standing for any run of characters and an
`issuer` matched exactly, and they need the `trust-root` they are checked
against: the Sigstore trusted root that says which certificate authorities
may issue and which transparency logs are believed. Naming identities
without a root, or a root without identities, is refused when the config
loads.

`verify.sources` names the key a Hugging Face repository must have signed
its own published file digests with, so `pack --oms-key` need not be passed
by hand. All of this is described in the [security
guide](../guides/security.md).

## Related environment variables

| Variable | Purpose |
|---|---|
| `PALAN_HOME` | store location override |
| `COSIGN_PASSWORD` | password for encrypted signing keys |
| `DOCKER_CONFIG` | where the Docker credentials store lives |
