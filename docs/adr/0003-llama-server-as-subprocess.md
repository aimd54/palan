# ADR-0003: Manage llama-server as a subprocess, not via cgo

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

moci serves GGUF models through llama.cpp. Two integration shapes exist:
embed llama.cpp via cgo bindings, or supervise stock `llama-server`
processes. llama.cpp moves fast (flags, API, and performance characteristics
churn across builds — design doc §15), inference crashes are a real
operational event, and air-gapped hosts need a way to receive runtime
updates without rebuilding tools.

## Decision

We will **manage, never embed,** `llama-server`: one subprocess per loaded
model, health-checked over its `/health` endpoint, terminated with SIGTERM
on unload. Runtime binaries are version-pinned per moci minor release and
distributed as OCI artifacts (`runtimes/llama-server:<build>-<flavor>`)
through the same registries as the models. cgo bindings are rejected.

## Consequences

- A llama.cpp crash kills one model's process, not the router; recovery is
  a respawn.
- Runtime upgrades and rollbacks are artifact pulls, not binary rebuilds —
  and they traverse the air gap through the already-established channel.
- moci binaries stay CGO_ENABLED=0, keeping cross-compilation and static
  distribution trivial.
- Cost: process supervision, port allocation, and readiness probing are
  moci's job (`internal/runtime`), and llama.cpp CLI-flag churn is isolated
  behind one tested pin per release rather than eliminated.
