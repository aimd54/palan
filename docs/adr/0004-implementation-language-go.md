# ADR-0004: Implement in Go

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

The workload is I/O-bound transfer, process supervision, and HTTP/SSE
proxying — inference performance lives entirely in llama.cpp regardless of
client language (design doc §12). Language choice is therefore about
ecosystem leverage. The canonical OCI client libraries (oras-go v2,
go-containerregistry, containerd) are Go; every reference peer in this space
(Ollama, zot, ORAS, KitOps, modctl) is Go; and the daemonless goal requires
single static binaries, which disqualifies interpreter-dependent stacks.

## Decision

We will implement moci in **Go (≥ 1.24)**, CGO disabled, with a lean core
dependency set: oras-go v2, cobra + viper, sigstore-go,
prometheus/client_golang, and an in-repo ~200-line GGUF header reader
instead of a heavyweight parsing dependency.

## Consequences

- Static cross-compiled binaries for linux/amd64, linux/arm64, darwin/arm64
  come essentially for free (goreleaser).
- We inherit battle-tested OCI plumbing instead of rewriting it (see
  ADR-0005); patterns can be cribbed from the Go-based peers.
- Rust remains a respectable alternative on paper; rewriting oras-go's
  maturity was judged negative-value work (§12). Revisit only if the Go
  OCI ecosystem stalls.
