// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"regexp"
	"strings"
	"testing"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/attest"
	"github.com/aimd54/palan/internal/registrytest"
	"github.com/aimd54/palan/internal/store"
)

// runVerifyIn runs the real verify command against a store the caller
// chooses, so a test can pull first and then ask about what landed.
func runVerifyIn(t *testing.T, home, ref string, args ...string) (string, error) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs(append([]string{ref}, args...))
	err := cmd.Execute()
	return out.String(), err
}

// runPullInto runs the real pull command, so the store under test holds
// exactly what a pull leaves behind rather than what a test assembled.
func runPullInto(t *testing.T, home, ref string) {
	t.Helper()
	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	cmd := newPullCmd(v)
	cmd.SetOut(io.Discard)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("pull: %v", err)
	}
}

// renderedVerdicts reads the text chain back into link name and verdict.
// Parsed rather than matched as a substring, because the columns are laid
// out by a tabwriter: their widths depend on which links happen to be
// present, so a hardcoded gap passes or fails for reasons that have nothing
// to do with the verdict under test.
// columnGap separates the columns tabwriter padded out.
var columnGap = regexp.MustCompile(`\s{2,}`)

func renderedVerdicts(t *testing.T, out string) map[string]string {
	t.Helper()
	verdicts := make(map[string]string)
	for _, line := range strings.Split(out, "\n") {
		trimmed := strings.TrimSpace(line)
		var verdict string
		switch {
		case strings.HasPrefix(trimmed, "proven "):
			verdict = "proven"
		case strings.HasPrefix(trimmed, "unproven "):
			verdict = "unproven"
		default:
			continue
		}
		// Columns, not a list of known names. A link name can be two
		// words, so it cannot be split off by position; keeping a copy of
		// the names here instead would mean a link added later is simply
		// absent from every test that reads this, which is the failure the
		// chain exists to prevent. The renderer pads its columns, so two
		// or more spaces is the boundary and a name keeps its single one.
		fields := columnGap.Split(trimmed, 3)
		if len(fields) == 3 {
			verdicts[fields[1]] = verdict
		}
	}
	return verdicts
}

// linkVerdicts reads the chain out of --json, which is the form a test can
// assert on without depending on column widths.
func linkVerdicts(t *testing.T, out string) map[string]link {
	t.Helper()
	var e explanation
	if err := json.Unmarshal([]byte(out), &e); err != nil {
		t.Fatalf("the --json output does not parse (%v), stream was: %q", err, out)
	}
	byName := make(map[string]link, len(e.Links))
	for _, l := range e.Links {
		byName[l.Name] = l
	}
	return byName
}

// signedUpstreamModel seeds a model whose layer records where it came from,
// signs it, and returns its reference and public key file.
func signedUpstreamModel(t *testing.T, reg *registrytest.Registry, weights []byte) (ref, pubKey string, layer ocispec.Descriptor) {
	t.Helper()
	reg.PutBlob("llm/tiny", weights)
	layer = sourceLayer(weights, "huggingface.co/org/repo", "model.gguf", "abc123", strings.Repeat("11", 32))
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{layer})
	priv, privKey := attestKeypair(t)
	pubKey = attestPubKeyFile(t, priv)
	ref = reg.Host() + "/llm/tiny:q4"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}
	return ref, pubKey, layer
}

func TestExplainNamesEveryLinkIncludingTheOnesItCannotProve(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))

	out, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--explain")
	if err != nil {
		t.Fatalf("verify --explain: %v", err)
	}
	rendered := renderedVerdicts(t, out)
	for name, want := range map[string]string{
		linkReference: "proven",
		linkSignature: "proven",
		linkPolicy:    "proven",
		linkSources:   "proven",
		linkContent:   "unproven",
	} {
		if got := rendered[name]; got != want {
			t.Errorf("the chain reads %q as %q, want %q; it was:\n%s", name, got, want, out)
		}
	}
	if !strings.Contains(out, "huggingface.co/org/repo@abc123") {
		t.Errorf("the provenance link does not name the source; the chain was:\n%s", out)
	}
	if !strings.Contains(out, "--rehash") {
		t.Errorf("the content link does not say what would prove it; the chain was:\n%s", out)
	}
	if !strings.Contains(out, "--key "+pubKey) {
		t.Errorf("the policy link does not name what admitted the signer; the chain was:\n%s", out)
	}
}

func TestExplainAsJSONIsTheWholeStreamAndCarriesTheSameVerdicts(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))

	out, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--json")
	if err != nil {
		t.Fatalf("verify --json: %v", err)
	}
	links := linkVerdicts(t, out)
	for _, name := range []string{linkReference, linkSignature, linkPolicy, linkSources, linkContent} {
		if _, ok := links[name]; !ok {
			t.Errorf("the JSON chain has no %q link; it was:\n%s", name, out)
		}
	}
	if !links[linkSources].Proven {
		t.Errorf("provenance reads unproven for an artifact whose attestation checked out: %+v", links[linkSources])
	}
	if links[linkContent].Proven {
		t.Errorf("content reads proven though no blob was read back: %+v", links[linkContent])
	}
}

func TestExplainSaysAnArtifactPackedLocallyNamesNoSource(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights")
	reg.PutBlob("llm/local", weights)
	seedModel(t, reg, "llm/local", "v1", []ocispec.Descriptor{localLayer(weights, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	ref := reg.Host() + "/llm/local:v1"
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	out, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--json")
	if err != nil {
		t.Fatalf("verify --json: %v", err)
	}
	links := linkVerdicts(t, out)
	if links[linkSources].Proven {
		t.Errorf("an artifact with no upstream reads as having proven provenance: %+v", links[linkSources])
	}
	if !strings.Contains(links[linkSources].Detail, "local disk") {
		t.Errorf("the provenance link does not distinguish a local pack from a missing statement: %+v", links[linkSources])
	}
}

func TestRehashReadsTheBlobsBackAndSaysHowMany(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))
	runPullInto(t, home, ref)

	out, err := runVerifyIn(t, home, ref, "--key", pubKey, "--json", "--rehash")
	if err != nil {
		t.Fatalf("verify --rehash: %v", err)
	}
	links := linkVerdicts(t, out)
	if !links[linkContent].Proven {
		t.Fatalf("content reads unproven after a re-hash: %+v", links[linkContent])
	}
	// The manifest, its config, and the one weight layer.
	if !strings.Contains(links[linkContent].Detail, "3 blobs") {
		t.Errorf("the content link does not say what was read: %+v", links[linkContent])
	}
}

// TestSignatureVerifiesOverSubstitutedWeightsUntilTheBlobsAreReadBack is the
// gap ADR-0008 deferred, shown from both sides in one test: the same store,
// the same signature, and two different answers depending on whether the
// bytes were read. Asserting only the refusal would leave it unclear that
// there was ever anything to close.
func TestSignatureVerifiesOverSubstitutedWeightsUntilTheBlobsAreReadBack(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	original := []byte("the weights a publisher released")
	ref, pubKey, layer := signedUpstreamModel(t, reg, original)
	runPullInto(t, home, ref)

	st, err := store.Open(context.Background(), home)
	if err != nil {
		t.Fatal(err)
	}
	path, err := st.BlobPath(layer.Digest)
	if err != nil {
		t.Fatalf("the weight blob is not in the store after a pull: %v", err)
	}
	substituted := []byte("the weights an attacker wrote!!!")
	if len(substituted) != len(original) {
		t.Fatalf("the substitution must be the same length, got %d against %d", len(substituted), len(original))
	}
	if err := os.Chmod(path, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, substituted, 0o600); err != nil {
		t.Fatal(err)
	}

	// The manifest is untouched, so the signature still verifies. This is
	// the state an operator would read as a verified model.
	if _, err := runVerifyIn(t, home, ref, "--key", pubKey); err != nil {
		t.Fatalf("the signature must still verify over a substituted blob, or this test is not about the gap: %v", err)
	}

	_, err = runVerifyIn(t, home, ref, "--key", pubKey, "--rehash")
	if err == nil {
		t.Fatal("--rehash accepted a substituted weight blob")
	}
	if !strings.Contains(err.Error(), layer.Digest.String()) {
		t.Errorf("the refusal does not name the blob that changed: %v", err)
	}
}

func TestRehashRefusesWhenTheBlobsAreNotOnThisHost(t *testing.T) {
	reg := registrytest.New(t)
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))

	_, err := runVerifyIn(t, t.TempDir(), ref, "--key", pubKey, "--rehash")
	if err == nil {
		t.Fatal("--rehash reported on blobs that are not in the local store")
	}
	if !strings.Contains(err.Error(), "not in the local store") {
		t.Errorf("the refusal does not say why there was nothing to read: %v", err)
	}
}

// TestVerifyRefusesWhenTheStoreHoldsADifferentArtifactUnderTheSameTag
// covers the case that would otherwise read as a pass: a tag that moved on
// the registry while this host kept the old copy and never held a
// signature, so the signature is checked against what the registry serves
// now while the blobs here belong to the artifact from before.
//
// Nothing about the signature is wrong, which is what makes this the
// dangerous shape. The refusal can only come from comparing what verified
// against what this host holds, and it has to come without --rehash being
// asked for: an operator gating a rollout on verify has no second chance,
// and run would go on to refuse the same reference on the same host.
func TestVerifyRefusesWhenTheStoreHoldsADifferentArtifactUnderTheSameTag(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref := reg.Host() + "/llm/tiny:q4"

	// The copy this host pulled, before anything was signed, so the store
	// holds the model and no signature for it.
	first := []byte("the weights this host pulled")
	reg.PutBlob("llm/tiny", first)
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{localLayer(first, "model.gguf")})
	runPullInto(t, home, ref)

	// The publisher moves the tag to a new artifact and signs that one.
	second := []byte("the weights the tag points at now")
	reg.PutBlob("llm/tiny", second)
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{localLayer(second, "model.gguf")})
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the moved tag: %v", err)
	}

	// The signature is good and covers the artifact the tag names now.
	// What is wrong is that this host holds a different one under that
	// reference, and saying "Verified" here would be a verdict about a
	// copy that is somewhere else.
	_, err := runVerifyIn(t, home, ref, "--key", pubKey)
	if err == nil {
		t.Fatal("verify passed while this host holds a different artifact under the verified reference")
	}
	if !strings.Contains(err.Error(), "not the one that verified") {
		t.Errorf("the refusal does not say the artifact here is not the verified one: %v", err)
	}

	// Refused before any blob is read, rather than after: the digests
	// settle it, and reading whole weight files to reach the same answer
	// would be gigabytes spent on a question already decided.
	if _, err := runVerifyIn(t, home, ref, "--key", pubKey, "--rehash"); err == nil {
		t.Fatal("--rehash reported on blobs belonging to a different artifact")
	}
}

// TestExplainNamesWhatDatesAKeylessSignature: a Fulcio certificate lives
// minutes, so the log entry is what supplies a moment to hold it to. A chain
// that reported the signer without saying what dated it would leave the
// reader with no way to look the signature up.
//
// The same fixture covers the gap on the other side. A source attestation is
// checked against the key that signed the model, and a keyless signature
// supplies an identity instead, so these layers name an upstream that
// nothing here vouches for. That has to read as unproven rather than as
// silence.
func TestExplainNamesWhatDatesAKeylessSignature(t *testing.T) {
	reg := registrytest.New(t)
	weights := []byte("weights signed without a key")
	reg.PutBlob("llm/qwen3", weights)
	layer := sourceLayer(weights, "huggingface.co/org/repo", "model.gguf", "abc123", strings.Repeat("11", 32))
	ref, l := seedKeylessModel(t, reg, []ocispec.Descriptor{layer})
	root := writeTrustRootFile(t, l)

	t.Setenv("PALAN_HOME", t.TempDir())
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyPolicy, keylessPolicy(reg.Host(), root, keylessSigner.Subject, keylessSigner.Issuer))
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verifying a keyless signature: %v", err)
	}

	links := linkVerdicts(t, out.String())
	log, ok := links[linkLog]
	if !ok {
		t.Fatalf("the chain has no transparency log link; it was:\n%s", out.String())
	}
	if !strings.Contains(log.Detail, "entry ") {
		t.Errorf("the log link does not locate the entry: %+v", log)
	}
	if !strings.Contains(log.Detail, root) {
		t.Errorf("the log link does not name the root its proof was rebuilt against: %+v", log)
	}
	if !strings.Contains(links[linkSignature].Detail, keylessSigner.Subject) {
		t.Errorf("the signature link does not name who signed: %+v", links[linkSignature])
	}
	if links[linkSources].Proven {
		t.Errorf("provenance reads proven beside a keyless signature, which supplies no key to check it with: %+v", links[linkSources])
	}
	if !strings.Contains(links[linkSources].Detail, "upstream source") {
		t.Errorf("the provenance link does not say what was left unchecked: %+v", links[linkSources])
	}
}

// TestVerifyReadsTheBlobsBackWhenTheConfigAsksRatherThanTheFlag: the guide
// offers verify.rehash and the flag as the same instruction, so a host that
// sets the config and audits with verify --explain must not be told the
// content link is unproven.
func TestVerifyReadsTheBlobsBackWhenTheConfigAsksRatherThanTheFlag(t *testing.T) {
	reg := registrytest.New(t)
	home := t.TempDir()
	ref, pubKey, _ := signedUpstreamModel(t, reg, []byte("weights"))
	runPullInto(t, home, ref)

	t.Setenv("PALAN_HOME", home)
	v := viper.New()
	v.Set(keyRegistryPlainHTTP, true)
	v.Set(keyVerifyRehash, true)
	cmd := newVerifyCmd(v)
	var out bytes.Buffer
	cmd.SetOut(&out)
	cmd.SetErr(io.Discard)
	cmd.SetArgs([]string{ref, "--key", pubKey, "--json"})
	if err := cmd.Execute(); err != nil {
		t.Fatalf("verify under verify.rehash: %v", err)
	}
	links := linkVerdicts(t, out.String())
	if !links[linkContent].Proven {
		t.Fatalf("verify.rehash in the config left the content link unproven: %+v", links[linkContent])
	}
	if !strings.Contains(links[linkContent].Detail, "3 blobs") {
		t.Errorf("the content link does not say what was read: %+v", links[linkContent])
	}
}

// TestExplainSaysWhetherThisHostHoldsTheArtifact: every link above this one
// can be true of a copy that is somewhere else. The signature is read from
// the registry whenever the store holds a model without holding its
// signature, and verifying before pulling anything at all is ordinary. A
// chain that stopped at the signature would describe the registry's copy
// and read as though it described this host.
func TestExplainSaysWhetherThisHostHoldsTheArtifact(t *testing.T) {
	reg := registrytest.New(t)
	body := []byte("weights this host will come to hold")
	reg.PutBlob("llm/tiny", body)
	seedModel(t, reg, "llm/tiny", "q4", []ocispec.Descriptor{localLayer(body, "model.gguf")})
	ref := reg.Host() + "/llm/tiny:q4"
	priv, privKey := attestKeypair(t)
	pubKey := attestPubKeyFile(t, priv)
	if err := runSign(t, ref, privKey); err != nil {
		t.Fatalf("signing the fixture: %v", err)
	}

	// Nothing pulled yet. Verifying is legitimate and must succeed; what
	// the chain may not do is imply the bytes are here.
	home := t.TempDir()
	out, err := runVerifyIn(t, home, ref, "--key", pubKey, "--explain")
	if err != nil {
		t.Fatalf("verifying before pulling must work: %v", err)
	}
	if got := renderedVerdicts(t, out)[linkLocal]; got != "unproven" {
		t.Errorf("a host holding nothing reports the local copy as %q", got)
	}

	runPullInto(t, home, ref)
	out, err = runVerifyIn(t, home, ref, "--key", pubKey, "--explain")
	if err != nil {
		t.Fatalf("verifying what was just pulled: %v", err)
	}
	if got := renderedVerdicts(t, out)[linkLocal]; got != "proven" {
		t.Errorf("the artifact is on this host and the local copy reports %q", got)
	}
}

// TestProvenanceCannotForgeARowInTheChain: a repository and a revision are
// read from layer annotations, which nothing constrains to printable text,
// and the chain is a column layout a person reads. A newline inside one of
// them draws an extra row, and a row can be made to read "proven", which is
// the one claim this output exists to make. A signer the policy admits is
// enough to plant one, so the artifact's own bytes must not be able to
// write the verdict printed beside them.
func TestProvenanceCannotForgeARowInTheChain(t *testing.T) {
	forged := "example.com/repo\n  proven    content   4 blobs re-read, every digest matches"
	lines := provenanceLines([]attest.Layer{{Repo: forged, Revision: "abc123"}})
	if len(lines) != 1 {
		t.Fatalf("one layer produced %d lines", len(lines))
	}
	if strings.ContainsAny(lines[0], "\n\r\x1b") {
		t.Fatalf("a layer annotation put a control character into the chain: %q", lines[0])
	}

	// The escaping only applies where there is something to hide, so an
	// ordinary reference still reads as itself.
	plain := provenanceLines([]attest.Layer{{Repo: "huggingface.co/org/repo", Revision: "abc123"}})
	if len(plain) != 1 || plain[0] != "huggingface.co/org/repo@abc123" {
		t.Errorf("an ordinary source is not printed plainly: %q", plain)
	}
}
