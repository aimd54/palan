# ADR-0001: Build moci on standard OCI registries and the ModelPack format

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

The existing air-gapped LLM distribution stack (FastAPI registry + MinIO +
custom pull/push scripts) has structural limits inherent to a bespoke
protocol: no content addressing, no dedup, no resumable transfers, no
signing/provenance, and no ecosystem interoperability (design doc §2).
Between 2024 and 2026 the industry converged on OCI registries as the
distribution substrate for models: CNCF ModelPack standardizes the artifact
format, Kubernetes 1.36 shipped image volumes as GA citing model mounting,
and zot/Harbor natively store such artifacts (§2, §4).

The design doc defined an M0 decision gate: try the workflow with existing
tools (zot + Ollama's OCI dialect; zot + RamaLama under Podman) before
writing code (§4). Those trials require the target deployment environment
and were not run; the maintainer reviewed the trade-off analysis and
directed the build on 2026-07-12, accepting local-only validation. The
doc's predictions — Ollama chafing on auth/naming against standard
registries (issues #2745, #7244, #4204, #9409), RamaLama's hard
container-engine requirement — are recorded here as *unverified
expectations*: if hands-on trials later contradict them, the "adopt
instead of build" option should be re-examined.

## Decision

We will build `moci` as **client and serving layer only**, targeting any
OCI 1.1-conformant registry, packaging models per the **CNCF ModelPack
specification** (`application/vnd.cncf.model.*` media types) with custom
metadata carried exclusively in annotations (`io.moci.*`). We will not build
a registry server, and we will not invent media types.

## Consequences

- Registry-side features (auth, GC, replication, UI, storage drivers) are
  inherited from off-the-shelf registries instead of hand-built.
- Interoperability with `oras`, `modctl`, KitOps, Harbor, and Kubernetes
  becomes a testable contract (see the interop test suite) rather than a hope.
- moci's fate is coupled to the ModelPack spec (CNCF sandbox); spec types are
  isolated in `pkg/modelspec` so drift is contained and detectable.
- The niche claimed is "daemonless + standard OCI + managed llama.cpp
  serving"; if Ollama ships first-class custom registries, part of the
  differentiation erodes (accepted risk, §15).
