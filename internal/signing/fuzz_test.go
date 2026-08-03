// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package signing

import (
	"bytes"
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"io"
	"testing"

	"github.com/opencontainers/go-digest"
	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/sigstore/sigstore/pkg/cryptoutils"
	"github.com/sigstore/sigstore/pkg/signature"
	sigoptions "github.com/sigstore/sigstore/pkg/signature/options"
	"oras.land/oras-go/v2/content"
	"oras.land/oras-go/v2/errdef"
)

// memTarget is a minimal oras.ReadOnlyTarget over an in-memory blob map, so
// the fuzzer drives signature handling without a disk layout in the loop.
type memTarget struct {
	root  ocispec.Descriptor
	blobs map[digest.Digest][]byte
}

func (m *memTarget) Resolve(_ context.Context, _ string) (ocispec.Descriptor, error) {
	if m.root.Digest == "" {
		return ocispec.Descriptor{}, errdef.ErrNotFound
	}
	return m.root, nil
}

func (m *memTarget) Fetch(_ context.Context, target ocispec.Descriptor) (io.ReadCloser, error) {
	b, ok := m.blobs[target.Digest]
	if !ok {
		return nil, errdef.ErrNotFound
	}
	return io.NopCloser(bytes.NewReader(b)), nil
}

func (m *memTarget) Exists(_ context.Context, target ocispec.Descriptor) (bool, error) {
	_, ok := m.blobs[target.Digest]
	return ok, nil
}

// FuzzVerify feeds arbitrary bytes through signature verification. A transfer
// bundle is attacker-controlled, and Verify now reads one directly, so the
// manifest and payload it parses are untrusted input.
//
// Two invariants: verification must never panic, and it must never accept
// anything but the exact bytes that were genuinely signed. A crafted manifest
// returning a nil error would be a signature bypass.
func FuzzVerify(f *testing.F) {
	ctx := context.Background()
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		f.Fatal(err)
	}
	pubPEM, err := cryptoutils.MarshalPublicKeyToPEM(&priv.PublicKey)
	if err != nil {
		f.Fatal(err)
	}
	verifier, err := LoadVerifier(pubPEM)
	if err != nil {
		f.Fatal(err)
	}
	signer, err := signature.LoadECDSASigner(priv, crypto.SHA256)
	if err != nil {
		f.Fatal(err)
	}

	const repoRef = "registry.example/llm/tiny"
	subject := digest.FromString("subject")

	payload, err := buildPayload(repoRef, subject)
	if err != nil {
		f.Fatal(err)
	}
	sig, err := signer.SignMessage(bytes.NewReader(payload), sigoptions.WithContext(ctx))
	if err != nil {
		f.Fatal(err)
	}
	plDesc := content.NewDescriptorFromBytes(MediaTypeSimpleSigning, payload)
	plDesc.Annotations = map[string]string{AnnotationSignature: base64.StdEncoding.EncodeToString(sig)}
	cfg := []byte("{}")
	cfgDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageConfig, cfg)
	m := ocispec.Manifest{MediaType: ocispec.MediaTypeImageManifest, Config: cfgDesc, Layers: []ocispec.Descriptor{plDesc}}
	m.SchemaVersion = 2
	good, err := json.Marshal(m)
	if err != nil {
		f.Fatal(err)
	}

	f.Add(good)
	f.Add([]byte("{}"))
	f.Add([]byte(`{"schemaVersion":2,"layers":[]}`))
	f.Add([]byte(`{"layers":[{"mediaType":"` + MediaTypeSimpleSigning + `"}]}`))
	f.Add([]byte(`{"layers":[{"mediaType":"` + MediaTypeSimpleSigning +
		`","annotations":{"` + AnnotationSignature + `":"!!!not base64!!!"}}]}`))

	f.Fuzz(func(t *testing.T, manifest []byte) {
		mDesc := content.NewDescriptorFromBytes(ocispec.MediaTypeImageManifest, manifest)
		tgt := &memTarget{
			root: mDesc,
			blobs: map[digest.Digest][]byte{
				mDesc.Digest:   manifest,
				plDesc.Digest:  payload,
				cfgDesc.Digest: cfg,
			},
		}
		err := Verify(ctx, tgt, "irrelevant", repoRef, ocispec.Descriptor{Digest: subject}, verifier)
		if err == nil && !bytes.Equal(manifest, good) {
			t.Fatalf("verification accepted a manifest that was not the signed one: %q", manifest)
		}
	})
}
