// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package modelspec

import (
	"testing"
)

// TestSpecStringsPinned guards the exact wire strings this project depends
// on. If a ModelPack spec bump ever changes one of these, interop with
// already-published artifacts breaks — this test makes that a loud,
// reviewable event instead of a silent one (ADR-0005).
func TestSpecStringsPinned(t *testing.T) {
	pins := map[string]string{
		ArtifactTypeModelManifest:     "application/vnd.cncf.model.manifest.v1+json",
		MediaTypeModelConfig:          "application/vnd.cncf.model.config.v1+json",
		MediaTypeModelWeightRaw:       "application/vnd.cncf.model.weight.v1.raw",
		MediaTypeModelWeightConfigRaw: "application/vnd.cncf.model.weight.config.v1.raw",
		MediaTypeModelDocRaw:          "application/vnd.cncf.model.doc.v1.raw",
		AnnotationFilepath:            "org.cncf.model.filepath",
	}
	for got, want := range pins {
		if got != want {
			t.Errorf("spec string drifted: got %q, want %q", got, want)
		}
	}
}

func TestKindOf(t *testing.T) {
	cases := []struct {
		mediaType string
		want      LayerKind
	}{
		{MediaTypeModelWeightRaw, LayerKindWeight},
		{MediaTypeModelWeightZstd, LayerKindWeight},
		{MediaTypeModelWeightConfigRaw, LayerKindWeightConfig},
		{MediaTypeModelWeightConfigGzip, LayerKindWeightConfig},
		{MediaTypeModelDocRaw, LayerKindDoc},
		{MediaTypeModelCodeTar, LayerKindCode},
		{MediaTypeModelDatasetRaw, LayerKindDataset},
		{"application/vnd.oci.image.layer.v1.tar", LayerKindUnknown},
		{"", LayerKindUnknown},
		// Prefix confusion guard: weight.config must never classify as weight.
		{MediaTypeModelWeightConfigTar, LayerKindWeightConfig},
	}
	for _, c := range cases {
		if got := KindOf(c.mediaType); got != c.want {
			t.Errorf("KindOf(%q) = %v, want %v", c.mediaType, got, c.want)
		}
	}
}

func TestIsRaw(t *testing.T) {
	if !IsRaw(MediaTypeModelWeightRaw) {
		t.Error("weight raw should be raw")
	}
	if IsRaw(MediaTypeModelWeightTar) {
		t.Error("weight tar is not raw")
	}
	if IsRaw("application/vnd.example.v1.raw") {
		t.Error("unknown media types are never raw, even with a .raw suffix")
	}
}

func TestServeDefaultsRoundTrip(t *testing.T) {
	in := ServeDefaults{Ctx: 8192, NGL: 99, Flags: []string{"--flash-attn"}}
	enc, err := in.Encode()
	if err != nil {
		t.Fatalf("encode: %v", err)
	}
	out, err := ParseServeDefaults(enc)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if out.Ctx != in.Ctx || out.NGL != in.NGL || len(out.Flags) != 1 || out.Flags[0] != "--flash-attn" {
		t.Errorf("round trip mismatch: %+v != %+v", out, in)
	}
}

func TestServeDefaultsRejectsUnknownFields(t *testing.T) {
	if _, err := ParseServeDefaults(`{"ctx":4096,"typo_field":1}`); err == nil {
		t.Error("unknown fields must be rejected")
	}
}

func TestServeDefaultsRejectsGarbage(t *testing.T) {
	if _, err := ParseServeDefaults(`not json`); err == nil {
		t.Error("garbage must be rejected")
	}
}
