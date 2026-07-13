# Quickstart

Goal: from nothing to a served model in about five minutes, on one machine.

## Prerequisites

- A `moci` binary (release download, `go install github.com/aimd54/moci/cmd/moci@latest`, or `make build`)
- Docker (only for the throwaway registry)
- A GGUF model file (any quantization; for a small test try a
  SmolLM/stories-class model of a few hundred MB or less)
- `llama-server` from [llama.cpp](https://github.com/ggml-org/llama.cpp) in
  PATH — or pull one as a runtime artifact once your registry has one

## 1. Start a registry

```sh
docker run -d --rm --name zot -p 5000:5000 \
  ghcr.io/project-zot/zot-linux-amd64:v2.1.18
```

Everything below uses `--plain-http` because this registry has no TLS; with
a real registry, drop the flag. To avoid repeating flags, create
`~/.config/moci/config.yaml`:

```yaml
registry:
  default: localhost:5000
  plain-http: true
```

## 2. Pack and push

```sh
moci pack my-model.gguf -t llm/mymodel:q4 --ctx 8192 --push
```

`pack` reads the GGUF header and fills the ModelPack config (architecture,
quantization, size, license) — check with:

```sh
moci ls
moci ls --remote localhost:5000
```

## 3. Pull and run

```sh
moci rm llm/mymodel:q4 && moci gc     # simulate a second machine
moci pull llm/mymodel:q4
moci run llm/mymodel:q4               # interactive chat; /bye to quit
moci run llm/mymodel:q4 -p "One-line haiku about registries"
```

`run` spawns `llama-server` directly on the store's blob — the model is
never copied or unpacked.

## 4. Serve several models

```sh
moci serve
```

- OpenAI-compatible endpoint on `:11500` (`/v1/models`,
  `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`)
- models load lazily on first request and unload after `--idle-timeout`
- the memory budget (auto-detected; override with `--memory-budget 9GiB`)
  evicts least-recently-used models instead of overcommitting
- Prometheus metrics on `/metrics`

```sh
curl -s localhost:11500/v1/chat/completions -d '{
  "model": "localhost:5000/llm/mymodel:q4",
  "messages": [{"role":"user","content":"Say hi"}],
  "stream": true
}'
```

## 5. Where next

- Sign your models and enforce verification: [security guide](guides/security.md)
- Move models across an air gap: [air-gap guide](guides/air-gap.md)
- Serve from Kubernetes: [Kubernetes guide](guides/kubernetes.md)
- Distribute llama-server itself through the registry: `moci runtime --help`
