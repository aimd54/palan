# Copyright The palan Authors
# SPDX-License-Identifier: Apache-2.0
#
# Source for docs/assets/demo.gif. Edit this file and run `make demo`;
# never hand-edit the GIF.
#
# Recording prerequisites, all on the host:
#
#   - vhs and ttyd on PATH (https://github.com/charmbracelet/vhs)
#   - ffmpeg and gifsicle on PATH
#   - docker, for the registry the demo publishes to and then deletes
#   - cosign, to generate the key pair the demo signs with
#   - network access, since the model is fetched from Hugging Face
#
# What this records is the distribution path: publish, sign, refuse an
# unsigned artifact, then verify with the registry gone. Nothing on screen
# is model output, which is deliberate. A recording that ends on generated
# text is only as good as the model that happened to be loaded, and the
# quality of an answer is not what this tool decides.
#
# The recorded shell uses scratch PALAN_HOME directories throughout, because
# whatever appears on screen is baked into an image that no later search of
# this repository can find. A recording must never see a real store.
#
# The unsigned artifact carries a context size the signed one does not, so its
# annotations differ and so does its manifest digest. That difference is the
# whole point. A signature covers a digest rather than a tag, and a manifest
# does not record the repository it lives under, so the same bytes pushed to a
# second repository arrive on one digest and the first signature already covers
# them. An earlier draft pushed identical content and recorded a refusal that
# never happened.

Output docs/assets/demo.gif

Require palan
Require docker
Require cosign
Require curl

Set Shell "bash"
Set FontSize 16
Set Width 1200
Set Height 540
Set Padding 20
Set Framerate 20
Set TypingSpeed 30ms
Set WaitTimeout 180s
Set Theme "Catppuccin Mocha"
Set WindowBar Colorful

# Fixture work, hidden because it is not part of the story: a bare prompt,
# this tree's binary, a registry, a key pair, and a scratch store.
Hide
Type 'export PS1="$ "' Enter
Type 'export PATH="$PWD/bin:$PATH"' Enter
Type 'cd "$(mktemp -d)"' Enter
Type 'docker rm -f demozot >/dev/null 2>&1' Enter
Type 'docker run -d --rm --name demozot -p 5000:5000 ghcr.io/project-zot/zot-minimal-linux-amd64:v2.1.18 >/dev/null' Enter
Type 'until curl -sf localhost:5000/v2/ >/dev/null 2>&1; do sleep 1; done' Enter
Type 'COSIGN_PASSWORD=demo cosign generate-key-pair >/dev/null 2>&1' Enter
Type 'export PALAN_HOME="$(mktemp -d)"' Enter
Type "clear" Enter
Show

# One command fetches from Hugging Face, checks the bytes against the digest
# the repository publishes, packs, and pushes. The elapsed time in the GIF is
# the elapsed time of the transfer.
Type "palan pack hf://ggml-org/tiny-llamas/stories260K.gguf -t localhost:5000/llm/tiny:q4 --plain-http --push" Enter
Wait+Screen /Pushed/
Sleep 1500ms

Type "COSIGN_PASSWORD=demo palan sign localhost:5000/llm/tiny:q4 --key cosign.key --plain-http" Enter
Wait+Screen /Signed/
Sleep 2s

# Second artifact, unsigned, and the consumer's store. Hidden because it is
# setup for the refusal rather than the refusal itself.
Hide
Type 'palan pack hf://ggml-org/tiny-llamas/stories260K.gguf -t localhost:5000/llm/untrusted:q4 --ctx 4096 --plain-http --push >/dev/null 2>&1' Enter
Type 'export PALAN_HOME="$(mktemp -d)"' Enter
Type 'export PALAN_VERIFY_REQUIRED=true' Enter
Type 'export PALAN_VERIFY_KEY="$PWD/cosign.pub"' Enter
Type "clear" Enter
Show

Type "# a fresh store, on a host that requires a signature" Enter
Sleep 800ms

Type "palan pull localhost:5000/llm/untrusted:q4 --plain-http" Enter
Wait+Screen /no signature found/
Sleep 2s

# The refusal is only worth something if nothing arrived. Read the store
# rather than the exit code: an empty listing is the claim being made.
Type "palan ls" Enter
Wait+Screen /DIGEST/
Sleep 2500ms

Type "palan pull localhost:5000/llm/tiny:q4 --plain-http" Enter
Wait+Screen /Pulled/
Sleep 2s

# Verification reads the store, so it does not need the registry to exist.
Type "docker rm -f demozot" Enter
Sleep 1500ms

Type "palan verify localhost:5000/llm/tiny:q4 --key cosign.pub" Enter
Wait+Screen /source: local store/
Sleep 3s
