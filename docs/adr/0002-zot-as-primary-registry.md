# ADR-0002: zot as primary registry; client stays registry-agnostic

- Status: accepted
- Date: 2026-07-12
- Deciders: aimd54

## Context

moci needs a reference registry for development, e2e tests, and the
reference deployment. Candidates (design doc §6): **zot** (CNCF, single
static binary, OCI-native, S3 driver, OIDC, sync/mirroring, referrers, UI,
metrics), **distribution** (`registry:2`; simplest, no UI/OIDC/sync), and
**Harbor** (full platform; heavier, worth it mainly if wanted for container
images too).

The self-hosted, air-gap-first use case favors zot: its S3 storage driver
targets any S3-compatible store such as MinIO (with `redirectBlobURL: true`
streaming multi-GB blobs straight from object storage via presigned 307
redirects), OIDC covers both human and workload authentication, and its
sync extension covers cross-network mirroring for the air gap.

## Decision

We will use **zot** as the primary registry for deployment assets, e2e
tests, and documentation. The moci client, however, speaks only the OCI
Distribution Spec: **nothing in moci may depend on zot-specific behavior.**

## Consequences

- `deploy/` ships zot configuration (MinIO backend, TLS, OIDC, sync);
  alternatives are documented but not maintained as first-class assets.
- CI e2e runs against zot; the interop suite doubles as a guard that moci
  works against generic implementations.
- Registry-specific conveniences (zot's search extension, UI deep links) may
  be *used* by documentation but never *required* by code paths.
