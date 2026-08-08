# Architecture Decision Records

Significant architectural decisions are recorded here as ADRs, in the spirit
of [MADR](https://adr.github.io/madr/). An ADR is immutable once accepted:
if a decision changes, a new ADR supersedes the old one (which gets its
`Status` updated to `superseded by ADR-XXXX`), preserving the reasoning trail.

The overall system design lives in
[`docs/architecture.md`](../architecture.md); ADRs pin down individual
decisions and the reasoning behind them.

| ID | Title | Status |
|----|-------|--------|
| [ADR-0001](0001-build-on-oci-and-modelpack.md) | Build moci on standard OCI registries and the ModelPack format | accepted |
| [ADR-0002](0002-zot-as-primary-registry.md) | zot as primary registry; client stays registry-agnostic | accepted |
| [ADR-0003](0003-llama-server-as-subprocess.md) | Manage llama-server as a subprocess, not via cgo | accepted |
| [ADR-0004](0004-implementation-language-go.md) | Implement in Go | accepted |
| [ADR-0005](0005-transfer-backend-oras-go.md) | oras-go v2 as transfer backend; modctl as interop oracle | accepted |
| [ADR-0006](0006-rename-to-palan.md) | Rename the project from moci to palan | accepted |
| [ADR-0007](0007-signature-storage-and-verification.md) | Signatures travel as cosign tags and verify from any source | accepted |
| [ADR-0008](0008-verification-at-load-time.md) | Enforce the verification policy when a model is loaded | accepted |
| [ADR-0009](0009-hugging-face-as-a-pack-source.md) | Hugging Face as a pack source, compiled in and verified | accepted |
| [ADR-0010](0010-referrers-alongside-the-signature-tag.md) | Signatures are indexed as referrers as well as tagged (extends ADR-0007) | accepted |
| [ADR-0011](0011-terminal-output-is-decoration.md) | Terminal output is decoration; the machine-readable form is the contract | accepted |
| [ADR-0012](0012-distribution-is-format-neutral.md) | Distribution is format-neutral; serving is GGUF | accepted |

Use [`template.md`](template.md) for new ADRs.
