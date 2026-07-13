// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Package gguf reads GGUF file headers — just enough metadata to fill the
// ModelPack config at pack time (architecture, quantization, context
// length…), in ~200 lines instead of a heavyweight dependency (design §12).
//
// Layout (little-endian, versions 2 and 3):
//
//	magic "GGUF" | version u32 | tensorCount u64 | kvCount u64 | kvCount × KV
//
// where each KV is: string key | valueType u32 | value. Weights follow the
// header; this package never reads them. All variable-length fields are
// bounds-checked so a hostile file cannot balloon memory: model files are
// attacker-adjacent inputs (design §11).
package gguf

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"io"
	"math"
	"os"
	"strings"
)

// Magic is the GGUF file magic.
const Magic = "GGUF"

// Bounds on untrusted header fields.
const (
	maxKVCount   = 65536
	maxKeyLen    = 64 * 1024
	maxStringLen = 64 * 1024 * 1024 // chat templates and license texts stay far below this
	maxArrayLen  = 64 * 1024 * 1024 // tokenizer vocabularies are ~100k entries
)

// Value types per the GGUF spec.
const (
	typeUint8   = 0
	typeInt8    = 1
	typeUint16  = 2
	typeInt16   = 3
	typeUint32  = 4
	typeInt32   = 5
	typeFloat32 = 6
	typeBool    = 7
	typeString  = 8
	typeArray   = 9
	typeUint64  = 10
	typeInt64   = 11
	typeFloat64 = 12
)

var scalarSize = map[uint32]int64{
	typeUint8: 1, typeInt8: 1, typeBool: 1,
	typeUint16: 2, typeInt16: 2,
	typeUint32: 4, typeInt32: 4, typeFloat32: 4,
	typeUint64: 8, typeInt64: 8, typeFloat64: 8,
}

// Info is the metadata moci cares about, plus the raw scalar/string KVs.
type Info struct {
	Version       uint32
	TensorCount   uint64
	Architecture  string // general.architecture
	Name          string // general.name
	SizeLabel     string // general.size_label, e.g. "8B"
	License       string // general.license (SPDX id)
	Quantization  string // derived from general.file_type
	ContextLength uint64 // <architecture>.context_length
	// Metadata holds every scalar and string KV (arrays are skipped).
	Metadata map[string]any
}

// ReadFile reads the GGUF header of the file at path.
func ReadFile(path string) (*Info, error) {
	f, err := os.Open(path) // #nosec G304 -- caller-supplied model path is the point of this API
	if err != nil {
		return nil, err
	}
	defer func() { _ = f.Close() }()
	info, err := Read(f)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", path, err)
	}
	return info, nil
}

// Read parses a GGUF header from r.
func Read(r io.Reader) (*Info, error) {
	br := bufio.NewReaderSize(r, 1<<20)

	magic := make([]byte, 4)
	if _, err := io.ReadFull(br, magic); err != nil {
		return nil, fmt.Errorf("reading magic: %w", err)
	}
	if string(magic) != Magic {
		return nil, fmt.Errorf("not a GGUF file (magic %q)", magic)
	}

	var version uint32
	if err := binary.Read(br, binary.LittleEndian, &version); err != nil {
		return nil, fmt.Errorf("reading version: %w", err)
	}
	if version < 2 || version > 3 {
		return nil, fmt.Errorf("unsupported GGUF version %d (big-endian file or pre-v2 format?)", version)
	}

	var tensorCount, kvCount uint64
	if err := binary.Read(br, binary.LittleEndian, &tensorCount); err != nil {
		return nil, fmt.Errorf("reading tensor count: %w", err)
	}
	if err := binary.Read(br, binary.LittleEndian, &kvCount); err != nil {
		return nil, fmt.Errorf("reading KV count: %w", err)
	}
	if kvCount > maxKVCount {
		return nil, fmt.Errorf("implausible KV count %d", kvCount)
	}

	info := &Info{
		Version:     version,
		TensorCount: tensorCount,
		Metadata:    make(map[string]any),
	}
	for i := uint64(0); i < kvCount; i++ {
		key, err := readString(br, maxKeyLen)
		if err != nil {
			return nil, fmt.Errorf("KV %d key: %w", i, err)
		}
		var vt uint32
		if err := binary.Read(br, binary.LittleEndian, &vt); err != nil {
			return nil, fmt.Errorf("KV %q type: %w", key, err)
		}
		val, err := readValue(br, vt)
		if err != nil {
			return nil, fmt.Errorf("KV %q value: %w", key, err)
		}
		if val != nil {
			info.Metadata[key] = val
		}
	}

	info.derive()
	return info, nil
}

// derive fills the typed fields from the raw metadata.
func (in *Info) derive() {
	str := func(key string) string {
		s, _ := in.Metadata[key].(string)
		return s
	}
	in.Architecture = str("general.architecture")
	in.Name = str("general.name")
	in.SizeLabel = str("general.size_label")
	in.License = str("general.license")
	if ft, ok := asUint64(in.Metadata["general.file_type"]); ok && ft <= math.MaxUint32 {
		in.Quantization = fileTypeName(uint32(ft))
	}
	if in.Architecture != "" {
		if cl, ok := asUint64(in.Metadata[in.Architecture+".context_length"]); ok {
			in.ContextLength = cl
		}
	}
}

// readValue decodes one value; arrays are skipped and return nil.
func readValue(br *bufio.Reader, vt uint32) (any, error) {
	if size, ok := scalarSize[vt]; ok {
		return readScalar(br, vt, size)
	}
	switch vt {
	case typeString:
		return readString(br, maxStringLen)
	case typeArray:
		return nil, skipArray(br)
	default:
		return nil, fmt.Errorf("unknown value type %d", vt)
	}
}

func readScalar(br *bufio.Reader, vt uint32, size int64) (any, error) {
	buf := make([]byte, size)
	if _, err := io.ReadFull(br, buf); err != nil {
		return nil, err
	}
	le := binary.LittleEndian
	switch vt {
	case typeUint8:
		return uint64(buf[0]), nil
	case typeInt8:
		return int64(int8(buf[0])), nil
	case typeBool:
		return buf[0] != 0, nil
	case typeUint16:
		return uint64(le.Uint16(buf)), nil
	case typeInt16:
		return int64(int16(le.Uint16(buf))), nil
	case typeUint32:
		return uint64(le.Uint32(buf)), nil
	case typeInt32:
		return int64(int32(le.Uint32(buf))), nil
	case typeFloat32:
		return float64(math.Float32frombits(le.Uint32(buf))), nil
	case typeUint64:
		return le.Uint64(buf), nil
	case typeInt64:
		return int64(le.Uint64(buf)), nil
	case typeFloat64:
		return math.Float64frombits(le.Uint64(buf)), nil
	}
	return nil, fmt.Errorf("unhandled scalar type %d", vt)
}

// skipArray discards an array value without materializing it.
func skipArray(br *bufio.Reader) error {
	var elemType uint32
	if err := binary.Read(br, binary.LittleEndian, &elemType); err != nil {
		return err
	}
	var count uint64
	if err := binary.Read(br, binary.LittleEndian, &count); err != nil {
		return err
	}
	if count > maxArrayLen {
		return fmt.Errorf("implausible array length %d", count)
	}
	if size, ok := scalarSize[elemType]; ok {
		_, err := br.Discard(int(int64(count) * size))
		return err
	}
	if elemType == typeString {
		for i := uint64(0); i < count; i++ {
			if err := skipString(br, maxStringLen); err != nil {
				return err
			}
		}
		return nil
	}
	return fmt.Errorf("array of unsupported element type %d", elemType)
}

func readString(br *bufio.Reader, limit uint64) (string, error) {
	var n uint64
	if err := binary.Read(br, binary.LittleEndian, &n); err != nil {
		return "", err
	}
	if n > limit {
		return "", fmt.Errorf("string length %d exceeds limit %d", n, limit)
	}
	var sb strings.Builder
	if _, err := io.CopyN(&sb, br, int64(n)); err != nil {
		return "", err
	}
	return sb.String(), nil
}

func skipString(br *bufio.Reader, limit uint64) error {
	var n uint64
	if err := binary.Read(br, binary.LittleEndian, &n); err != nil {
		return err
	}
	if n > limit {
		return fmt.Errorf("string length %d exceeds limit %d", n, limit)
	}
	_, err := br.Discard(int(n))
	return err
}

func asUint64(v any) (uint64, bool) {
	switch x := v.(type) {
	case uint64:
		return x, true
	case int64:
		if x >= 0 {
			return uint64(x), true
		}
	}
	return 0, false
}
