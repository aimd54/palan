# Architecture Decision Records

Significant architectural decisions are recorded here as ADRs, in the spirit
of [MADR](https://adr.github.io/madr/). An ADR is immutable once accepted:
if a decision changes, a new ADR supersedes the old one (which gets its
`Status` updated to `superseded by ADR-XXXX`), preserving the reasoning trail.

The overall system design lives in
[`docs/design/oci-llm-distribution.md`](../design/oci-llm-distribution.md);
ADRs pin down the decisions that document left open.

| ID | Title | Status |
|----|-------|--------|
| [ADR-0001](0001-build-on-oci-and-modelpack.md) | Build moci on standard OCI registries and the ModelPack format | accepted |
| [ADR-0002](0002-zot-as-primary-registry.md) | zot as primary registry; client stays registry-agnostic | accepted |
| [ADR-0003](0003-llama-server-as-subprocess.md) | Manage llama-server as a subprocess, not via cgo | accepted |
| [ADR-0004](0004-implementation-language-go.md) | Implement in Go | accepted |
| [ADR-0005](0005-transfer-backend-oras-go.md) | oras-go v2 as transfer backend; modctl as interop oracle | accepted |
| [ADR-0006](0006-rename-to-palan.md) | Rename the project from moci to palan | accepted |

Use [`template.md`](template.md) for new ADRs.
