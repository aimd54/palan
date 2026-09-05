## palan run

Run a model interactively (pulling it if needed)

### Synopsis

Run ensures the model and a llama-server runtime are available, spawns
llama-server on the raw weight blob straight from the store (no copy), and
opens an interactive chat. With --prompt it answers once and exits; with
--web it serves llama-server's UI until interrupted.

```
palan run REF [flags]
```

### Examples

```
  # Interactive chat; /bye or Ctrl-D to leave
  palan run llm/qwen3:8b-q4

  # Answer one prompt and exit, for scripts
  palan run llm/qwen3:8b-q4 -p "One-line haiku about registries"
```

### Options

```
      --ctx int             context size override
  -h, --help                help for run
      --ngl int             GPU layer count override
  -p, --prompt string       answer this prompt once and exit
      --rehash              read the model's blobs back at load and hold each to the digest the manifest records
      --runtime string      runtime artifact reference (default: runtime.ref config, then PATH)
      --verify              require a valid signature before fetching or running the model
      --verify-key string   public key for --verify (default: verify.key from the config)
      --web                 expose llama-server's web UI instead of the terminal chat
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

