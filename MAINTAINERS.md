# Maintainers

| Name   | GitHub                                   | Role       |
|--------|------------------------------------------|------------|
| aimd54 | [@aimd54](https://github.com/aimd54)     | Maintainer |

Maintainers are responsible for reviewing and merging pull requests,
triaging issues, cutting releases, and handling security reports per
[SECURITY.md](SECURITY.md).

## Cutting a release

The version comes from build information, so no file in the tree records
it and nothing needs bumping. Release notes are generated from commit
subjects, grouped by their Conventional Commit prefix, which is one more
reason those prefixes have to be right when the commit is written rather
than when the release is cut.

Wait for every workflow to pass on the commit being tagged, not only the
one that looks relevant. CI, CodeQL, Docs and Scorecard each report
separately:

```sh
gh api repos/aimd54/palan/commits/<sha>/check-runs \
  --jq '.check_runs[] | "\(.conclusion)\t\(.name)"'
```

A skipped job is an answer; a pending one is not. A release build that
succeeds says the artifacts were produced, not that the code behind them
is sound, so it is not a substitute for the checks above. Version 0.3.0
shipped a reachable vulnerability that way and had to be superseded the
same week.

Then tag that commit by name, so the tag cannot land on whatever `HEAD`
has since become:

```sh
git tag -a v0.5.0 -m "palan v0.5.0" <sha>
git push origin v0.5.0
```

The tag is annotated and its message is the version and nothing else.
Pushing it is what publishes: the release workflow runs goreleaser and
then attaches provenance. A finished release carries nine files, and they
are worth checking by name rather than by count: three platform archives,
an SBOM beside each, `checksums.txt`, a sigstore bundle over the
checksums, and `multiple.intoto.jsonl`.

A pushed tag is final. Deleting, moving or force-updating anything under
`refs/tags/v*` is refused, because a signature covers a digest and a tag
is how a reader finds one: a tag that can be repointed makes verifying it
meaningless.

## Becoming a maintainer

Sustained, quality contributions (code, docs, reviews) over time; proposed
by an existing maintainer and recorded here via pull request.
