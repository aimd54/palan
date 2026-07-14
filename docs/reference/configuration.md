# Configuration reference

palan reads, in order of precedence (highest wins):

1. command-line flags
2. environment variables — `PALAN_` prefix, dots/dashes become underscores
   (e.g. `PALAN_REGISTRY_DEFAULT`, `PALAN_SERVE_BEARER_TOKEN`)
3. the config file — `--config PATH`, else `~/.config/palan/config.yaml`

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
  bearer-token: ""             # require Authorization: Bearer … when set

verify:
  required: false              # verify signatures on every pull
  key: ""                      # public key used when --verify-key is not passed
```

## Related environment variables

| Variable | Purpose |
|---|---|
| `PALAN_HOME` | store location override |
| `COSIGN_PASSWORD` | password for encrypted signing keys |
| `DOCKER_CONFIG` | where the Docker credentials store lives |
