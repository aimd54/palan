// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package keylesstest builds keyless signing material for tests: a
// certificate authority, a transparency log, and bundles signed by both.
//
// It exists because the interesting failures cannot be reached by editing a
// real bundle. Breaking a real inclusion proof to test what happens when a
// log entry is about somebody else's signature breaks the proof first, so
// the check under test never runs. A log that can be built to order can
// hold two genuine entries and offer a real proof of the wrong one.
package keylesstest

import (
	"crypto/sha256"
	"fmt"
)

// tree is an in-memory Merkle tree in the shape a transparency log uses
// (RFC 6962): leaves hashed under one prefix, interior nodes under another,
// so no leaf can be passed off as a subtree.
type tree struct {
	leaves [][]byte
}

func (t *tree) add(entry []byte) int {
	h := sha256.New()
	h.Write([]byte{0x00})
	h.Write(entry)
	t.leaves = append(t.leaves, h.Sum(nil))
	return len(t.leaves) - 1
}

func hashChildren(left, right []byte) []byte {
	h := sha256.New()
	h.Write([]byte{0x01})
	h.Write(left)
	h.Write(right)
	return h.Sum(nil)
}

// root returns the tree head over every leaf added so far.
func (t *tree) root() []byte {
	return subtreeRoot(t.leaves)
}

// subtreeRoot folds a run of leaves the way RFC 6962 splits them: the
// largest power of two that is strictly smaller than the count goes left,
// the remainder right, which is what makes the tree's shape independent of
// the order leaves arrived in.
func subtreeRoot(leaves [][]byte) []byte {
	switch len(leaves) {
	case 0:
		sum := sha256.Sum256(nil)
		return sum[:]
	case 1:
		return leaves[0]
	}
	k := split(len(leaves))
	return hashChildren(subtreeRoot(leaves[:k]), subtreeRoot(leaves[k:]))
}

// split returns the largest power of two strictly less than n.
func split(n int) int {
	k := 1
	for k*2 < n {
		k *= 2
	}
	return k
}

// inclusionProof returns the sibling hashes on the path from leaf index to
// the tree head, in the order a verifier consumes them: innermost first.
func (t *tree) inclusionProof(index int) ([][]byte, error) {
	if index < 0 || index >= len(t.leaves) {
		return nil, fmt.Errorf("entry %d is not in a log of %d entries", index, len(t.leaves))
	}
	return pathTo(t.leaves, index), nil
}

func pathTo(leaves [][]byte, index int) [][]byte {
	if len(leaves) <= 1 {
		return nil
	}
	k := split(len(leaves))
	if index < k {
		return append(pathTo(leaves[:k], index), subtreeRoot(leaves[k:]))
	}
	return append(pathTo(leaves[k:], index-k), subtreeRoot(leaves[:k]))
}
