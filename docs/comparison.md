# How palan compares

palan distributes model weights as OCI artifacts, verifies them before use, and
serves GGUF locally through llama.cpp.

Those are two separate jobs, and the neighbouring tools differ in which one
they do. For **distribution**: modctl, KitOps, ORAS and Docker Model Runner.
For **local serving**: Ollama, RamaLama and Docker Model Runner. A tool can be
strong at one and absent from the other, so the two are compared separately
below.

This page records where those tools stood as of August 2026. Any of it can go
out of date without notice, so corrections are welcome in
[Q&A](https://github.com/aimd54/palan/discussions/categories/q-a).

## Distribution

|                     | any standard registry | signature gate before use | air-gap bundles | no container runtime |
|---------------------|:---:|:---:|:---:|:---:|
| modctl              | ✓ | ✗ | ✗ | ✓ |
| KitOps              | ✓ | ✗ | ✓ | ✓ |
| ORAS                | ✓ | ✗ | ✓ | ✓ |
| Docker Model Runner | ✓ | not documented | ✗ | standalone `dmr` |
| Ollama              | own dialect | ✗ | manual blob copy | ✓ |
| **palan**           | ✓ | ✓ | ✓ | ✓ |

## Local serving

|                        | standard OCI registries | daemonless | managed multi-model serving |
|------------------------|:---:|:---:|:---:|
| Ollama                 | own dialect | ✓ | ✓ |
| RamaLama               | ✓ | containers by default | ✓ |
| Docker Model Runner    | ✓ | standalone `dmr` | not documented |
| modctl / KitOps / ORAS | ✓ | ✓ | ✗ |
| **palan**              | ✓ | ✓ | ✓ |

## What managed multi-model serving means here

Several models resident behind one OpenAI-compatible endpoint: loaded on first
request, unloaded when idle, and evicted by least-recent use when a configured
memory budget would otherwise be exceeded.

Loading a single model on demand is a weaker property and a common one. The
arbitration is the part that matters, because it decides whether a second model
on the same GPU evicts the first or fails the request.

## RamaLama

RamaLama runs a model in a container by default, preferring Podman and falling
back to Docker. When neither is installed it runs the model with software on
the local system. `--nocontainer` selects that path directly, documented as
"Do not run RamaLama workloads in containers (default: False)".

That mode also gives up OCI images and automatic GPU acceleration. Both a
standard registry and daemonless operation are therefore reachable, one at a
time rather than together.

## Docker Model Runner

Docker Model Runner pulls models as OCI artifacts from Docker Hub or any
OCI-compliant registry. It also ships `dmr`, described upstream as a single
self-contained binary bundling the inference daemon and the model-management
CLI, with no dependency on Docker Desktop or a running Docker Engine.

Docker's own overview still names Docker Desktop or Docker Engine as the
prerequisite and does not mention a standalone binary. Both statements are
recorded here rather than reconciled, so treat that column as moving.

Docker Model Runner loads a model into memory when a request arrives and
unloads it when idle. Whether it arbitrates several resident models against a
memory budget is not documented.

## Ollama

Ollama's registry is shaped like an OCI registry without being one. Ordinary
pull-through caches do not work against it. Authentication answers a 401
challenge by signing a server nonce with the user's SSH private key, a scheme
no standard registry implements. Pushing to and pulling from OCI registries
remains an open request upstream.

A custom registry prefix can be pointed at other hosts, which serves models to
Ollama clients. It does not make the artifacts readable by tools that read OCI
artifacts, which is the property this column measures.

## modctl, KitOps and ORAS

These package and move models without serving them, which is what they set out
to do.

ORAS is a general client for OCI artifacts. modctl packs and pushes ModelPack
artifacts. KitOps packages a model together with its code, configuration and
metadata into a ModelKit, and offers deployment paths into Kubernetes, KServe
and shared container runtimes; its documentation states that KitOps does not
provide inference serving, and that the inference endpoint, routing and serving
solution are the user's to supply.

palan reads and writes the same ModelPack artifacts, so these tools and palan
operate on each other's output. That interoperability is exercised in CI
against modctl, `oras` and `cosign` on every commit.

## Serving scope

palan serves GGUF through llama.cpp, and no other weight format. llama.cpp
cannot read safetensors, and vLLM is a Python process carrying CUDA and torch,
so it cannot travel as a static binary or start without a container runtime.
Serving it would cost the daemonless property, which is what lets palan run as
an init container and on hosts where no container engine is installed.

For safetensors, palan is the distribution and verification layer in front of
whichever inference stack is already running.

## Sources

- RamaLama options, including `--nocontainer`:
  <https://github.com/containers/ramalama/blob/main/docs/ramalama.1.md>
- RamaLama command reference: <https://ramalama.ai/docs/commands/ramalama/>
- Docker Model Runner upstream: <https://github.com/docker/model-runner>
- Docker Model Runner overview:
  <https://docs.docker.com/ai/model-runner/>
- Docker Model Runner general availability:
  <https://www.docker.com/blog/announcing-docker-model-runner-ga/>
- KitOps deployment documentation: <https://kitops.org/docs/deploy/>
- Ollama OCI registry request:
  <https://github.com/ollama/ollama/issues/2745>
