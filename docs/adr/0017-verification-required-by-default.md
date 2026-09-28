# ADR-0017: Verification is required by default, and local trust is by digest

- Status: proposed
- Date: 2026-09-28
- Deciders: aimd54

## Context

Every milestone since M8 built out one property: that the bytes a host
serves are the bytes a trusted party vouched for. The checks that make up
that property are all in place, and all of them are off unless asked for.

- `verify.required` defaults to false. With it set, or with `--verify`, it
  gates `pull` before anything downloads, every model `load` brings in,
  `runtime pull`, and `run` and `serve` at the moment a model is loaded
  ([ADR-0008](0008-verification-at-load-time.md)). Without it, none of
  those checks run, and nothing says so.
- Trust comes from `verify.key` or `verify.policy`. With neither set, a
  verification fails with "no verification key configured".
- `palan sign` signs a model on its registry. A model packed locally and
  never pushed cannot be signed, so under a required policy it could never
  be run. A store filled before signing existed is in the same position.
- The policy is the `verify:` section of the config file. The config
  reader ignores keys it does not know, so a misspelt `verify.requried: true`
  is silently a store with no verification, and nothing records which
  version of the format a file was written for.

A 1.0 is a statement about defaults as much as about features. Shipping it
with the property off means the host that most needs it, one set up once
and left alone, is the one least likely to have it.

## Decision

We will make **`verify.required` true by default**. `pull`, `load`,
`runtime pull`, `run` and `serve` verify unless `verify.required` is set to
false. A host with no key, no policy and nothing trusted is refused, and the
refusal names every way forward: a key, a policy, a trusted digest, or
turning verification off.

We will let an operator **trust an artifact by its digest**. `palan trust
add REF` records the manifest digest REF resolves to, and a trusted digest
satisfies verification wherever that content is loaded, under any name.
This is how a locally packed model, or a store that predates signing, is
admitted one artifact at a time without switching verification off.

- The trusted digests live in their own file in the config directory,
  beside the key and the policy, not in the store. A trust decision belongs
  with the other trust decisions, out of reach of whatever can write the
  store and swap a blob.
- A digest pins content, so trusting it under one name trusts it under
  every name. Names are not what verification protects.
- `trust add` refuses an artifact whose signature fails against the
  configured key or policy, because trusting it would hide a real failure.
  An artifact that would verify anyway is added with a note that it was
  not needed.
- A result satisfied by a trusted digest says so: `verify`, `--explain`,
  `ls` and `describe` report "trusted locally", never "verified".
- `pack` does not verify, since it creates the artifact, but it says that
  the result needs a signature or `trust add` before `run` will accept it.

We will make **the `verify:` section a stable, versioned format**. Its keys
and their meaning are documented as stable until 2.0. `verify.version`
names the format, and absent means 1. An unknown key under `verify:` is
refused when the config is read, so a typo is an error rather than a
policy that quietly does nothing.

## Consequences

- A fresh install cannot run an unsigned model until its operator decides
  how it is to be trusted. That is the point of the change, and the refusal
  is written to be the documentation for it.
- Upgrading a store that holds unsigned content stops `run` and `serve` on
  that content. The refusal lists the references and the command that
  admits them; `verify.required: false` restores the old behaviour.
- Scripts that pull unsigned models, the quickstart and the e2e suite need
  a key, a trusted digest, or an explicit `verify.required: false`.
- Trusting by digest adds a third kind of trust beside keys and keyless
  identities. It is local by construction: nothing about it travels with
  the artifact, so a bundle carried to another host has to be trusted, or
  signed, there as well.
- Refusing unknown keys under `verify:` can break a config that carried a
  misspelt or retired key. That is the intended failure; other sections
  keep their current tolerance.
- Revisit the digest-trust store if palan gains multi-user stores, where
  one user's trust decision should not become another's.
