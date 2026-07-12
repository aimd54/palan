# Security Policy

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Use GitHub's private vulnerability reporting:
**Security → Report a vulnerability** on this repository
(<https://github.com/aimd54/moci/security/advisories/new>).

You can expect an acknowledgement within 7 days. Reports are triaged,
fixed privately, and disclosed via a GitHub Security Advisory once a
patched release is available.

## Supported versions

Pre-1.0, only the latest minor release line receives security fixes.

## Scope notes

Model weights are attacker-controlled inputs: moci verifies blob digests on
every transfer and supports cosign signature verification on pull
(`moci pull --verify`, `verify.required` in the config). Weaknesses in those
guarantees — digest bypass, signature confusion, path traversal during
unpacking, `--insecure` behavior beyond its documented warning — are all
in scope and highly appreciated reports.
