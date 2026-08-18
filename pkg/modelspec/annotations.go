// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package modelspec

import (
	"encoding/json"
	"fmt"
	"strings"
)

// palan-specific annotation keys. These extend ModelPack artifacts through
// the spec's sanctioned extension point (annotations) and never change layer
// or config media types.
const (
	// AnnotationOriginSHA256 ties the artifact to the upstream file it was
	// packed from: the SHA-256 of the original (e.g. Hugging Face) GGUF.
	AnnotationOriginSHA256 = "io.palan.origin.sha256"

	// AnnotationServeDefaults carries JSON-encoded ServeDefaults chosen at
	// pack time, applied by `palan run`/`palan serve` unless overridden.
	AnnotationServeDefaults = "io.palan.serve.defaults"

	// AnnotationContextLength is the model's maximum context length in
	// tokens, as a decimal string (read from the GGUF header at pack time).
	// The upstream ModelConfig has no such field.
	AnnotationContextLength = "io.palan.model.context_length"

	// AnnotationOriginSigner names the key whose signature over the
	// publisher's own file digests was checked at import, as sha256:<hex>
	// of the public key. Absent when no such signature was verified.
	AnnotationOriginSigner = "io.palan.origin.signer"

	// AnnotationSourceRepo names the repository a layer's file was fetched
	// from, host included, for example huggingface.co/Qwen/Qwen3-8B.
	// Absent on a file packed from local disk.
	AnnotationSourceRepo = "io.palan.source.repo"

	// AnnotationSourcePath is the file's path within that repository.
	AnnotationSourcePath = "io.palan.source.path"

	// AnnotationSourceRevision is the commit the repository reported for the
	// listing the file was fetched from. Absent when the repository stated
	// none, since a revision that was never reported is not a fact about the
	// model.
	AnnotationSourceRevision = "io.palan.source.revision"
)

// ServeDefaults are default llama-server parameters embedded at pack time
// (value format of AnnotationServeDefaults), e.g. {"ctx":8192,"ngl":99}.
type ServeDefaults struct {
	// Ctx is the context size to serve with (llama-server --ctx-size).
	Ctx int `json:"ctx,omitempty"`
	// NGL is the number of layers to offload to the GPU (--n-gpu-layers).
	NGL int `json:"ngl,omitempty"`
	// Flags are additional raw llama-server flags, appended last.
	Flags []string `json:"flags,omitempty"`
}

// ParseServeDefaults decodes the AnnotationServeDefaults value. Unknown
// fields are rejected so typos surface at pack time rather than serve time.
func ParseServeDefaults(s string) (ServeDefaults, error) {
	var d ServeDefaults
	dec := json.NewDecoder(strings.NewReader(s))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&d); err != nil {
		return ServeDefaults{}, fmt.Errorf("parsing %s: %w", AnnotationServeDefaults, err)
	}
	return d, nil
}

// Encode returns the canonical JSON annotation value.
func (d ServeDefaults) Encode() (string, error) {
	b, err := json.Marshal(d)
	if err != nil {
		return "", fmt.Errorf("encoding %s: %w", AnnotationServeDefaults, err)
	}
	return string(b), nil
}
