# ADR-0011: Terminal output is decoration, and the machine-readable form is the contract

- Status: accepted
- Date: 2026-08-05
- Deciders: aimd54

## Context

palan is used almost entirely from a terminal, and its output had not had the
attention its internals had. Listings and detail views were `text/tabwriter`
with no emphasis, help was stock cobra, and the interactive chat printed the
model's token stream verbatim, so a reply arrived with its markdown markers
intact and offered no line editing, no history, and no sign of activity before
the first token.

Improving that means taking on a terminal-UI stack, which pulls against a value
this project has held from the start: few runtime dependencies. The direct
count went from 13 to 18, and the change is visible in the artefact that ships.

Measured on 2026-08-05, `linux/amd64`, `CGO_ENABLED=0 -trimpath -ldflags "-s -w"`,
by building with each piece removed:

| Build | Size | Added |
|---|---|---|
| Before this work | 15.31 MB | |
| plus lipgloss and fang | 16.72 MB | 1.41 MB |
| plus bubbletea and bubbles | 17.92 MB | 1.20 MB |
| plus glamour | 23.70 MB | **5.77 MB** |
| plus the list widget | 24.17 MB | 0.48 MB |

Markdown rendering is 65% of the growth, nearly all of it the syntax
highlighter's language corpus, for a feature that only appears in `palan run`.
That was raised as a decision on its own rather than absorbed, and it was taken
deliberately: an LLM's replies are markdown, code blocks are the most common
thing in them, and a 5.8 MB binary sits beside model files measured in
gigabytes.

Two other things were checked rather than assumed. `fang` names a pre-release
of its styling library in its own `go.mod`, but a `require` there is a minimum
rather than a pin, so naming a stable version here raises the whole build; the
result compiles and runs, and no pre-release is in the tree. And the styling
library's zero-value style renders its input unchanged, which is what lets the
plain path stay plain by construction.

## Decision

We adopt a terminal-UI stack, and we bound what it is allowed to be
responsible for:

> **The machine-readable output is the contract.** `--json`, exit codes, and
> plain text are the interface. Styling is decoration, is confined to
> terminals, and must never be the only thing carrying a piece of information.

Concretely, and enforceable in review:

- A colour or weight may emphasise something the text already says. It may not
  be the only way to know it. A reader with `NO_COLOR` set loses nothing but
  emphasis.
- Whatever a non-terminal destination receives is a compatibility surface.
  Changing it is a breaking change, not a visual one, and golden files record
  it so a diff is evidence rather than opinion.
- One package decides whether styling happens, and it is the only importer of
  the styling library. When styling is off it hands back styles that render
  their input unchanged, so callers do not branch and cannot forget.
- Interactive interfaces are offered only when a terminal is present on both
  ends. Without one, the previous behaviour stands, including a missing
  argument staying an error rather than becoming a prompt.

## Consequences

- The interactive chat renders replies as markdown, keeps history and line
  editing, and leaves finished turns in the terminal's scrollback. Listings
  gain emphasis. Help, errors, shell completions and a man page come from the
  command framework's wrapper.
- The binary grew by 58%. Anyone distributing palan through an air gap carries
  8.9 MB more per platform.
- Two renderers exist for listings, deliberately. `tabwriter` measures columns
  in bytes, so an escape sequence in any column but the last destroys the
  alignment the table exists for. Terminals get a renderer that measures
  displayed width; everything else keeps the original. Both build their columns
  from one definition so they cannot drift.
- Anything that is not a terminal keeps byte-identical output, asserted by
  golden files rather than by intent. A second set of assertions walks the
  styled path for every value it should show, because the golden files would be
  satisfied by a styled renderer that had quietly dropped a column.
- `--no-color` is named for what it does. That convention governs colour, and a
  library honouring it may still emit bold or reset sequences; palan's own
  output emits nothing at all, which is stricter than the convention asks.
- Terminal interfaces are hard to test by driving a terminal, so they are
  tested as state machines: a completed chat turn records both sides, a failed
  one drops the question that produced it rather than silently resending it,
  and input arriving mid-turn is ignored rather than crossing two replies.
- Revisit if the binary becomes a real constraint, or if a terminal interface
  ever becomes the only way to do something. The second would breach the rule
  above; the first is a size problem with a known cause and a known remedy.
