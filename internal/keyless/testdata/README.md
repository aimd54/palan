# Test fixtures

These two files are real material from the public Sigstore instance, copied
unchanged from the Sigstore projects. They are here so that this package is
tested against bundles and roots it did not produce itself: a mistake in the
wire formats fails against them, where it would pass against material
written by the same misunderstanding that reads it.

| File | Copied from | Licence |
|---|---|---|
| `trusted-root-public-good.json` | `sigstore/sigstore-go`, `examples/` | Apache-2.0 |
| `public-good-bundle.json` | `sigstore/cosign`, `pkg/cosign/testdata/` | Apache-2.0 |

The bundle is a keyless signature made in February 2025. Its signing
certificate expired ten minutes after it was issued, which is what makes it
useful: verification can only succeed by checking the certificate against
the moment the signature was recorded in the transparency log, so a build
that checked it against the present would fail here.

Neither file is reachable from the palan binary, and neither is a secret.
A trusted root is public keys and certificate authorities, published so that
anyone can pin it.
