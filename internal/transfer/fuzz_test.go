// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package transfer

import (
	"archive/tar"
	"bytes"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// FuzzUntarDir exercises bundle extraction. `palan load` unpacks a tar the
// user carried in from somewhere else, so the traversal, absolute-path, and
// link rejections in untarDir are a security boundary rather than a
// convenience. The invariant checked here is containment: whatever the input,
// nothing may be written outside the extraction directory.
func FuzzUntarDir(f *testing.F) {
	f.Add(tarBytes(tar.Header{Typeflag: tar.TypeDir, Name: "blobs/", Mode: 0o755}, nil))
	f.Add(tarBytes(tar.Header{Typeflag: tar.TypeReg, Name: "index.json", Mode: 0o644}, []byte(`{}`)))
	f.Add(tarBytes(tar.Header{Typeflag: tar.TypeReg, Name: "../escape", Mode: 0o644}, []byte("x")))
	f.Add(tarBytes(tar.Header{Typeflag: tar.TypeReg, Name: "/abs", Mode: 0o644}, []byte("x")))
	f.Add(tarBytes(tar.Header{Typeflag: tar.TypeSymlink, Name: "link", Linkname: "/etc/passwd"}, nil))
	f.Add(tarBytes(tar.Header{Typeflag: tar.TypeReg, Name: "big", Mode: 0o644, Size: 1 << 40}, []byte("short")))
	f.Add([]byte("not a tar"))
	f.Add([]byte{})

	f.Fuzz(func(t *testing.T, data []byte) {
		// Extract into a subdirectory so an escape lands in the parent,
		// where it is visible to the walk below.
		parent := t.TempDir()
		root := filepath.Join(parent, "root")
		if err := os.MkdirAll(root, 0o750); err != nil {
			t.Fatal(err)
		}

		_ = untarDir(bytes.NewReader(data), root) // errors are a fine outcome

		err := filepath.WalkDir(parent, func(p string, d fs.DirEntry, err error) error {
			if err != nil {
				return err
			}
			if p == parent || p == root || strings.HasPrefix(p, root+string(filepath.Separator)) {
				return nil
			}
			t.Fatalf("extraction escaped %s: wrote %s", root, p)
			return nil
		})
		if err != nil {
			t.Fatalf("walking extraction dir: %v", err)
		}
	})
}

// tarBytes builds a one-entry tar stream for the seed corpus.
func tarBytes(hdr tar.Header, body []byte) []byte {
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	if hdr.Size == 0 {
		hdr.Size = int64(len(body))
	}
	if err := tw.WriteHeader(&hdr); err != nil {
		return buf.Bytes()
	}
	_, _ = tw.Write(body)
	_ = tw.Close()
	return buf.Bytes()
}
