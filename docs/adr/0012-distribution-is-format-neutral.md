# ADR-0012: Distribution is format-neutral, serving is GGUF

- Status: accepted
- Date: 2026-08-08
- Deciders: aimd54

## Context

palan packs a model by reading a GGUF header, so a safetensors model cannot
enter the system at all. safetensors is the format model repositories publish
weights in, and a GGUF is a conversion of one, so the gap sits at the front of
every workflow that starts from a published repository rather than from a file
someone already converted.

No behaviour past packing depends on the weight format:

- Weight layers travel raw. `application/vnd.cncf.model.weight.v1.raw` names
  no format, and the ModelPack config carries a `format` field that
  distinguishes one from another. palan writes `gguf` there and shows it in
  `ls`, in `describe` and in their JSON output. Nothing branches on the value.
- Push, pull, signing, verification, garbage collection, offline bundles and
  the car profile address layers by digest and media type. None of them parses
  a weight file.
- `internal/pack` reads the GGUF header for six values: architecture, name,
  size label, quantization, license and context length. Every one is a property
  of a model rather than a property of GGUF. A safetensors repository publishes
  some of them: architecture and context length sit in `config.json`, and a
  parameter count comes from summing the tensor shapes in the file's JSON
  header. It publishes no license, and unquantized weights have no quantization
  to state.

Serving is where the formats genuinely diverge. llama.cpp reads GGUF and
nothing else, so a safetensors artifact has no runtime under
[ADR-0003](0003-llama-server-as-subprocess.md). The server the ecosystem uses
for safetensors is vLLM, a Python process that brings CUDA and torch with it.
It cannot be compiled into a static binary, and it cannot start without either
a container runtime or a Python environment provisioned on the host.

palan ships as one `CGO_ENABLED=0` binary that supervises child processes and
runs no daemon of its own. That property is what lets it work as an init
container beside any inference image, and on hosts where no container engine is
installed.

Teams serving safetensors in production already run vLLM under KServe or KAITO.
palan's work sits upstream of inference: a signed, digest-pinned path from a
publisher into a disconnected cluster, and a check at load time that the
weights are the ones the publisher signed. Both are format-neutral in
everything except the reader at the front.

## Decision

We will make **distribution, verification and air-gap handling
format-neutral**, and **keep serving on GGUF**.

- `pack` accepts a safetensors model, including a sharded one, which is packed
  whole or refused rather than in part. The ModelPack config records
  `format: safetensors`.
- Metadata reading fills one format-neutral record through a constructor per
  format, and the rest of `pack` reads that record instead of a weight file.
  Format-specific code stays in the readers, in the gathering of the files a
  model consists of, and in the refusal of an input set that mixes the two.
- Everything downstream of `pack` is unchanged, because none of it reads
  weights. A safetensors artifact pushes, pulls, signs, verifies, mirrors
  through an air gap and mounts as a volume on the same code path a GGUF does.
- `serve` and `run` serve GGUF and refuse anything else, in a message that
  names the format the artifact declares and says llama.cpp cannot load it.

Two alternatives would remove the serving limit. Both are rejected.

**Launching vLLM in a container from palan.** Serving would then require a
container runtime on the serving host, which is the dependency the
single-binary design exists to avoid, and the init-container and bare-host
deployments would lose the ability to serve at all. It would also put palan in
charge of a lifecycle it does not own: image pulls, GPU device plumbing,
restart policy and scheduling are an orchestrator's work, and reproducing them
behind `palan serve` means maintaining a weaker second orchestrator.

**Converting safetensors to GGUF during `pack`.** Conversion selects a
quantization, so the publisher would fix one choice for every consumer, and the
artifact would then hold bytes palan produced rather than the bytes upstream
released. A signature over it attests to the conversion instead of the model,
which undoes the provenance that
[ADR-0009](0009-hugging-face-as-a-pack-source.md) established by checking every
download against the digest its repository publishes. Conversion is also slow
and memory-hungry enough to change what `pack` is, which today is a
byte-preserving operation over files already on disk.

## Consequences

- A safetensors model can be packed, signed, distributed, verified offline and
  mounted into a pod. The init-container, image-volume and KServe patterns work
  with one, since none of them asks palan to run inference.
- `serve` and `run` gain a refusal that a GGUF user never meets. It names the
  format and points at the deployment shape that does work, because a bare
  "unsupported format" sends the reader hunting for a flag that does not exist.
- The config's `format` field becomes load-bearing. It has been display only,
  where a missing value cost a reader one dash in a column; serving now decides
  on it, so an artifact that omits it has to be handled explicitly rather than
  read as GGUF by default.
- Metadata coverage differs by format, and an artifact shows it. A GGUF header
  states quantization, context length and a license; a safetensors repository
  states architecture and context length in `config.json`, leaves `--license`
  as the only source of a license, and has no quantization to report for
  weights that were never quantized. A field with no source stays empty rather
  than being inferred.
- `io.palan.serve.defaults` and the flags that populate it describe llama.cpp's
  command line, so they carry no meaning on an artifact that will not be served
  here.
- The `FORMAT` column in `ls` and the `Format` field in `describe` have shown
  one value for every artifact in a store. They start discriminating, and they
  become how a user tells an artifact `serve` will load from one it refuses,
  ahead of trying it.
- Revisit the serving limit when a safetensors runtime exists that can be
  supervised the way `llama-server` is: one executable, pinned per release and
  delivered as an OCI artifact, with no interpreter or GPU library stack to
  provision around it. Serving that keeps the single static binary, keeps palan
  free of a daemon, and keeps `serve` working on an init container and on hosts
  with no container engine.
