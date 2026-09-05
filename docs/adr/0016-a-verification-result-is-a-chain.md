# ADR-0016: A verification result is a chain, and its gaps are named

- Status: accepted
- Date: 2026-09-04
- Deciders: aimd54

## Context

Verification could answer one question, and answered it well: is this model
signed by an identity the policy allows. Four things sat outside that answer,
each of them a link an operator would reasonably assume was covered.

- **The output was a verdict, not a chain.** `palan verify` printed
  `Verified`, the source, and a provenance line where one existed. Nothing
  said which links had not been established, so an artifact whose provenance
  was never checked and one whose provenance checked out produced outputs
  that differed only by an absent line.
- **Nothing read the weights back.**
  [ADR-0008](0008-verification-at-load-time.md) named this and deferred it:
  a signature covers a manifest, a manifest names blobs by digest, and no
  step opens a weight file. It set a condition for revisiting, an attacker
  who can write blobs but not manifests. A store on shared or removable
  storage is that attacker's opportunity, and it is the ordinary case for an
  air-gapped host, which is the host this project exists for.
- **The gate compared nothing between what verified and what loads.** A
  store can hold a model without holding its signature, in which case
  source selection reads the registry. With the tag moved since this host
  pulled, the registry's copy is signed, the host's copy is what it
  fetched, and `run` and `serve` loaded the second on the strength of the
  first. Both halves are individually correct, which is why it survived
  three milestones of verification work.
- **The engine was never checked, at either of the two layers it has.** A
  runtime artifact is the executable that reads the weights. It travels the
  same registries and is signed the same way, and `runtime pull`, `run` and
  `serve` took it unverified under a policy that refused unsigned models.
  Verifying the artifact is not the end of it either: palan unpacks a
  runtime into a plain directory under the store and executes it from
  there, so the file that runs is a copy outside the content-addressed
  store, and its presence says nothing about its bytes.

## Decision

We will make a verification result **a chain whose gaps are printed**.
`palan verify --explain` lists each link between the reference and the bytes
with a verdict of its own, and `--json` renders the same value for a
program. Unproven links are printed on every run, including for an artifact
palan did not produce, because a chain shown with its gaps removed reads as
a chain with no gaps. Text and JSON render from one value, so they cannot
come to disagree about what was proven.

We will **read the blobs back on request**, at `verify` with `--rehash` and
at load with `--rehash` or `verify.rehash`. It runs wherever it was asked
for, with or without a signature check configured beside it: the two answer
different questions, and a host that asked only for the re-read must not be
met with silence. It stays opt-in, because it re-reads whole weight files on
every load and after every eviction, which is the cost that led ADR-0008 to
defer it.

We will **hold the resident copy to the artifact that verified**, always,
with no flag. That comparison is a digest against a digest and costs
nothing, and the failure it catches is not a corrupted store but a correct
one being vouched for by a signature over something else.

We will **put the runtime channel through the same gate**, at `runtime
pull` and again before an engine is unpacked or spawned, and we will **hold
the unpacked tree to the manifest** before the entrypoint is executed,
discarding it and unpacking again when it does not match. The tree is
compared whole rather than file by file, because palan points the dynamic
loader at that directory, so a library added beside the binary is loaded
without any packed file being touched. Anything that is not a regular file
is refused rather than followed, since a symlink to a file holding the right
bytes satisfies a check that reads through it and leaves whoever owns the
target deciding what runs afterwards. The unpack that installs the
replacement holds each blob to its digest as it copies, because a store blob
is addressed by its file name and by nothing else, so reading one back is a
plain file open. That last check takes no flag: it is the object that
actually runs, and an engine is measured in megabytes where a model is
measured in gigabytes.

A runtime's name, build, flavour and entrypoint are read from the artifact's
own config blob and joined into the path that unpacking removes and
rewrites, so we will refuse any of them that is not a single path component,
and refuse an entrypoint the artifact does not carry. Path joining cleans a
traversal into a real path rather than rejecting it, which makes this the
difference between materialising an engine and unlinking a directory a
publisher chose.

Where no runtime artifact is configured and `llama-server` comes from
`PATH`, `run` and `serve` say so, because silence would read the same as an
engine that was checked.

## Consequences

- "Prove what is on this host" is one command's output, and the answer
  distinguishes an artifact that names no upstream from one whose statement
  is missing. Both previously printed nothing.
- A host that turns on `verify.rehash` pays a full read of the weights per
  load. On a multi-gigabyte model served from a spinning disk that is the
  dominant cost of the load, which is why it is not the default and why the
  guide names the situations that earn it: shared storage, removable
  storage, anywhere something other than palan can write to the store.
- The resident-copy comparison changes behaviour for a host that holds a
  model without its signature while the tag has moved. It served the older
  copy silently and now refuses, naming both digests. That is a break, and
  the intended one.
- A cluster running the gate pattern gets a refusal that writes nothing and
  returns. Both are measured against a real registry rather than asserted,
  the first by reading the output directory rather than the exit status,
  the second by holding stdin open so that a command deciding to prompt
  would hang rather than fail.
- An unpacked engine that does not match is replaced rather than reported,
  and the replacement is built whole before the old tree is taken away, so
  a failed unpack leaves a host with the engine it had rather than with
  none. Because the unpack verifies each blob as it copies, this is both
  the repair for an extraction that went wrong and the answer to one that
  was tampered with, and it restores the idempotence `Ensure` claims: its
  result depends on what the store holds rather than on what is already on
  disk.
- Signature verification and re-reading remain separate steps with separate
  costs. Folding them together would mean either paying gigabytes of I/O to
  answer whether something is signed, or reporting a re-read that never
  happened.
- Still not checked, and none of it closed here: the signed certificate
  timestamp inside a keyless certificate; a source attestation beside a
  keyless signature, which is checked against the key that signed the model
  and so is reported unchecked; a `llama-server` taken from `PATH`, which is
  reported rather than refused, since refusing it would strand every host
  serving with a distribution package; and the engine `serve` is running,
  which is checked once when the process starts while each model is
  re-checked on every load, so a long-running `serve` will not notice an
  engine that changes underneath it; and the interval between a check and
  the use it authorises, since a writer with access to the store can act
  after the digest was read and before the file is mapped or executed.
- Anything palan copies out of the content-addressed store is verified as
  it is written, which now covers unpacking an engine and materialising a
  model into a directory with `pull --output`. A file that has left the
  store is addressed by its name alone, and it is what something else goes
  on to read: an init container writes the model into a volume a serving
  container mounts. The general rule is that leaving the store is the
  moment to check, because nothing downstream can. Containment belongs to
  that check rather than beside it: a layer may name a nested file, so a
  write is resolved beneath the directory it was given, or verified bytes
  land outside the one that was asked for. Checking the components first
  and opening afterwards is not enough, since the path is resolved again at
  open time.
- Revisit the opt-in default at 1.0. If `verify.required` becomes the
  default and the cost of a re-read proves acceptable on the hardware
  people actually serve from, the two should probably move together.
