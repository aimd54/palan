# Quickstart

Goal: from nothing to a served model in about five minutes, on one machine.

## Prerequisites

- A `palan` binary (release download, `go install github.com/aimd54/palan/cmd/palan@latest`, or `make build`)
- Docker (only for the throwaway registry)
- A GGUF model file (any quantization; for a small test try a
  SmolLM/stories-class model of a few hundred MB or less). If you have
  models in Ollama or want one from Hugging Face, see
  [Importing models you already have](#importing-models-you-already-have).
- `llama-server` in PATH, from a
  [llama.cpp install](https://github.com/ggml-org/llama.cpp/blob/master/docs/install.md)
  (Homebrew, winget, conda-forge, MacPorts, or Nix), or pulled as a runtime
  artifact once your registry has one

## 1. Start a registry

```sh
docker run -d --rm --name zot -p 5000:5000 \
  ghcr.io/project-zot/zot-linux-amd64:v2.1.18
```

Everything below uses `--plain-http` because this registry has no TLS; with
a real registry, drop the flag. To avoid repeating flags, create
`~/.config/palan/config.yaml`:

```yaml
registry:
  default: localhost:5000
  plain-http: true
```

## 2. Pack and push

```sh
palan pack my-model.gguf -t llm/mymodel:q4 --ctx 8192 --push
```

`pack` reads the GGUF header and fills the ModelPack config (architecture,
quantization, size, license). Check with:

```sh
palan ls
palan ls --remote localhost:5000
```

## 3. Pull and run

```sh
palan rm llm/mymodel:q4 && palan gc     # simulate a second machine
palan pull llm/mymodel:q4
palan run llm/mymodel:q4               # interactive chat; /bye to quit
palan run llm/mymodel:q4 -p "One-line haiku about registries"
palan run                              # choose from the store
```

`run` spawns `llama-server` directly on the store's blob; the model is
never copied or unpacked.

At a terminal, replies are rendered as markdown once they finish arriving, so
headings, lists and code blocks read as such. Naming no model opens a
filterable list of what is in the store; `rm` does the same.

Everything above works the same when the output is a pipe or a file, only
without the formatting: no colour, no list, and a missing model reference stays
an error rather than a prompt. Colour also goes away under `NO_COLOR` or
`--no-color`, and `GLAMOUR_STYLE=light` suits a light terminal.

## 4. Serve several models

```sh
palan serve
```

- OpenAI-compatible endpoint on `:11500` (`/v1/models`,
  `/v1/chat/completions`, `/v1/completions`, `/v1/embeddings`)
- models load lazily on first request and unload after `--idle-timeout`
- the memory budget (auto-detected; override with `--memory-budget 9GiB`)
  evicts least-recently-used models instead of overcommitting
- Prometheus metrics on `/metrics`

On a GPU host, pack with `--ngl` so the model carries its own offload
setting:

```sh
palan pack mymodel.gguf -t llm/mymodel:q4 --ctx 8192 --ngl 99 --push
```

`serve` passes `--n-gpu-layers` only when the model's
`io.palan.serve.defaults` sets it. Recent `llama-server` builds offload
everything by default, which hides the difference. On a build that defaults
to none, an unset `ngl` serves from CPU with no warning. Check with
`palan describe`, and confirm the GPU is really in use:

```sh
nvidia-smi --query-compute-apps=pid,used_memory,process_name --format=csv
```

```sh
curl -s localhost:11500/v1/chat/completions -d '{
  "model": "localhost:5000/llm/mymodel:q4",
  "messages": [{"role":"user","content":"Say hi"}],
  "stream": true
}'
```

## Importing models you already have

### From Ollama

Ollama stores each model as an OCI manifest whose `model` layer is a plain,
unmodified GGUF file, so it can be packed as-is. Copy that layer out along
with the license layer:

```sh
OLLAMA=~/.ollama/models
MANIFEST=$OLLAMA/manifests/registry.ollama.ai/library/gemma3/1b
blob() { jq -r ".layers[]|select(.mediaType|endswith(\".$1\"))|.digest" \
           "$MANIFEST" | tr ':' '-'; }

cp "$OLLAMA/blobs/$(blob model)"   gemma3-1b.gguf
cp "$OLLAMA/blobs/$(blob license)" LICENSE

palan pack gemma3-1b.gguf LICENSE -t llm/gemma3:1b \
  --source https://ai.google.dev/gemma --push
```

File names decide the layer roles: `.gguf` becomes the weight layer, and
`LICENSE` a documentation layer that travels with the weights. Because the
weight bytes are unchanged, the `io.palan.origin.sha256` annotation on the
result is the same digest Ollama stored the blob under, which chains
provenance back to where the file came from.

Ollama's `template` and `params` layers use Ollama's own formats and are not
useful to `llama-server`. Most GGUFs already carry the chat template in the
header as `tokenizer.chat_template`.

### From Hugging Face

Name the file as an `hf://` source and `pack` fetches it:

```sh
palan pack hf://Qwen/Qwen3-8B-GGUF/Qwen3-8B-Q4_K_M.gguf \
  -t llm/qwen3:8b-q4 --push
```

The download is checked against the SHA-256 the repository publishes and
refused if the bytes differ, so a truncated or substituted file fails here
rather than being packed and signed as genuine. That digest becomes
`io.palan.origin.sha256` and the repository page becomes the source
annotation, without either having to be passed by hand.

Two things happen automatically because getting them wrong is easy. A model
split across `model-00001-of-00003.gguf` and its siblings brings every part,
since packing only the part you named produces an artifact that looks
complete and cannot load. And a `LICENSE` file in the repository travels with
the weights as a documentation layer.

Naming a safetensors repository without a file packs the whole model
through its shard index. A GGUF repository named without a file lists what
it publishes instead, since more than one quantisation usually lives
there:

```sh
palan pack hf://Qwen/Qwen3-8B-GGUF -t llm/qwen3:8b-q4
# available: Qwen3-8B-Q4_K_M.gguf, Qwen3-8B-Q5_0.gguf, ...
```

Gated repositories read `HF_TOKEN`; accept the model's terms first. A
repository that publishes only safetensors packs directly; producing
something `palan serve` can load still needs llama.cpp's
`convert_hf_to_gguf.py` first, since serving reads GGUF only.

Fetching from Hugging Face is a connected-side convenience, for seeding a
registry that offline sites then mirror from. Nothing about it is needed to
pull, serve, or verify a model.

### Licensing

Packing does not modify the weights, so redistribution is governed by the
model's own license. Several widely used families, including Gemma and
Llama, permit redistribution on the condition that the license text and
attribution notices stay with the weights. Packing the license file as a
layer satisfies that mechanically, and `palan pack` also lifts
`general.license` from the GGUF header into the ModelPack config when the
file sets it.

Mirroring into a registry you control is what palan is built for.
Publishing a model onward makes you its distributor, with the notice and
acceptable-use obligations that follow, and models kept behind terms
acceptance upstream should stay inside infrastructure you control.

## Where next

- Sign your models and enforce verification: [security guide](guides/security.md)
- Move models across an air gap: [air-gap guide](guides/air-gap.md)
- Serve from Kubernetes: [Kubernetes guide](guides/kubernetes.md)
- Distribute llama-server itself through the registry: `palan runtime --help`
