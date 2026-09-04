// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package keyless

import (
	"bytes"
	"crypto/sha256"
	"fmt"
	"testing"
)

// The inclusion proof is the one piece of cryptography here that palan
// implements rather than borrows, and it is written iteratively with bit
// arithmetic because that is how a log verifier is written. The tests
// below hold it against a reference written the other way: recursively,
// straight from the RFC 6962 definition, with no bit tricks and no shared
// code. Two implementations that disagree cannot both be right, and a
// mistake in the one under test does not survive being checked against a
// definition it does not share.

// referenceRoot computes a Merkle tree head the way RFC 6962 defines it,
// by splitting at the largest power of two below the leaf count.
func referenceRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		return leaves[0]
	}
	k := referenceSplit(len(leaves))
	l, r := referenceRoot(leaves[:k]), referenceRoot(leaves[k:])
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(l)
	h.Write(r)
	return h.Sum(nil)
}

// referencePath collects the sibling hashes from a leaf up to the head,
// innermost first, which is the order a verifier consumes them.
func referencePath(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := referenceSplit(len(leaves))
	if index < k {
		return append(referencePath(leaves[:k], index), referenceRoot(leaves[k:]))
	}
	return append(referencePath(leaves[k:], index-k), referenceRoot(leaves[:k]))
}

func referenceSplit(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

func referenceLeaves(n int) [][]byte {
	out := make([][]byte, n)
	for i := range out {
		h := sha256.New()
		h.Write([]byte{0x00})
		fmt.Fprintf(h, "entry %d", i)
		out[i] = h.Sum(nil)
	}
	return out
}

// TestTheInclusionProofAgreesWithTheDefinition walks every entry of every
// tree up to 64 leaves. That covers the cases a hand-picked table tends to
// miss: the last leaf of a full tree, the first leaf of an unbalanced one,
// sizes either side of a power of two, and every position in between.
func TestTheInclusionProofAgreesWithTheDefinition(t *testing.T) {
	for size := 1; size <= 64; size++ {
		leaves := referenceLeaves(size)
		want := referenceRoot(leaves)
		for index := 0; index < size; index++ {
			proof := referencePath(leaves, index)
			got, err := rootFromInclusionProof(int64(index), int64(size), leaves[index], proof)
			if err != nil {
				t.Fatalf("size %d, entry %d: %v", size, index, err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("size %d, entry %d: rebuilt a different head", size, index)
			}
		}
	}
}

// TestAProofIsRefusedForAnEntryOutsideTheTree covers the arithmetic that
// decides how many hashes a proof needs, which is where an index or a size
// out of range would otherwise be read as a shorter tree.
func TestAProofIsRefusedForAnEntryOutsideTheTree(t *testing.T) {
	leaves := referenceLeaves(8)
	proof := referencePath(leaves, 3)

	for _, tc := range []struct {
		name        string
		index, size int64
	}{
		{"the entry after the last", 8, 8},
		{"far beyond the tree", 1 << 40, 8},
		{"a negative entry", -1, 8},
		{"an empty tree", 0, 0},
		{"a negative tree", 0, -1},
		{"the largest index there is", 1<<63 - 1, 8},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if _, err := rootFromInclusionProof(tc.index, tc.size, leaves[3], proof); err == nil {
				t.Errorf("entry %d of %d was accepted", tc.index, tc.size)
			}
		})
	}
}

// TestAProofOfTheWrongLengthIsRefusedAtEverySize pins the exact-length
// rule across the whole range. A proof consumed as far as it goes rebuilds
// the head of a subtree, and comparing that against a signed log root is a
// different question from the one being asked.
func TestAProofOfTheWrongLengthIsRefusedAtEverySize(t *testing.T) {
	for size := 2; size <= 32; size++ {
		leaves := referenceLeaves(size)
		for index := 0; index < size; index++ {
			proof := referencePath(leaves, index)
			short := proof[:len(proof)-1]
			if _, err := rootFromInclusionProof(int64(index), int64(size), leaves[index], short); err == nil {
				t.Fatalf("size %d, entry %d: a proof one hash short was accepted", size, index)
			}
			long := append(append([][]byte{}, proof...), leaves[0])
			if _, err := rootFromInclusionProof(int64(index), int64(size), leaves[index], long); err == nil {
				t.Fatalf("size %d, entry %d: a proof one hash long was accepted", size, index)
			}
		}
	}
}

// TestAProofHashOfTheWrongSizeIsRefused: a short hash would otherwise be
// concatenated into the next node and quietly change what is being hashed.
func TestAProofHashOfTheWrongSizeIsRefused(t *testing.T) {
	leaves := referenceLeaves(8)
	proof := referencePath(leaves, 3)
	proof[1] = proof[1][:16]

	if _, err := rootFromInclusionProof(3, 8, leaves[3], proof); err == nil {
		t.Error("a proof carrying a half-length hash was accepted")
	}
}

// TestAnEntryOutsideTheTreeIsRefusedEvenWithAWellSizedProof isolates the
// range check from the length check.
//
// The cases above are all refused because a bogus index makes the required
// proof length disagree with the proof supplied, so they would pass with
// the range check deleted entirely. Entry 8 of a tree of 8 needs four
// hashes by the same arithmetic that a real entry 8 of a tree of 16 would,
// so handing it four leaves nothing but the range check standing.
func TestAnEntryOutsideTheTreeIsRefusedEvenWithAWellSizedProof(t *testing.T) {
	leaves := referenceLeaves(16)
	// The proof a real entry 8 would carry, which is the right length for
	// the entry-8-of-8 arithmetic too.
	wellSized := referencePath(leaves, 8)
	if len(wellSized) != 4 {
		t.Fatalf("entry 8 of 16 needs %d hashes, so this test no longer isolates the range check", len(wellSized))
	}

	if _, err := rootFromInclusionProof(8, 8, leaves[8], wellSized); err == nil {
		t.Error("entry 8 of a tree of 8 was accepted with a proof of the right length")
	}
}
