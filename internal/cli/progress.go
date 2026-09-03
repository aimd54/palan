// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"os"
	"sync"
	"sync/atomic"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/vbauerster/mpb/v8"
	"github.com/vbauerster/mpb/v8/decor"
	"golang.org/x/term"

	"github.com/aimd54/palan/internal/transfer"
)

// progress renders per-blob transfer bars on stderr when attached to a
// terminal; otherwise it stays silent (blob counts only).
type progress struct {
	p       *mpb.Progress
	mu      sync.Mutex
	bars    []*mpb.Bar
	skipped atomic.Int64
	// signed records whether a signature travelled with the artifact, so the
	// report can say that verification will work offline later.
	signed atomic.Bool
	// sigProblem records why a signature did not travel, when the reason was
	// a failure rather than the registry simply holding none.
	sigProblem error
	// attested records whether a source attestation travelled with the
	// artifact, so the report can say the provenance chain came along too.
	attested atomic.Bool
	// attProblem records why an attestation did not travel, when the reason
	// was a failure rather than the registry simply holding none.
	attProblem error
	// bundled records whether a keyless signature travelled with the
	// artifact, and bundleProblem why it did not when the reason was
	// something other than the registry holding none.
	bundled       atomic.Bool
	bundleProblem error
}

func newProgress(quiet bool) *progress {
	pr := &progress{}
	if !quiet && term.IsTerminal(int(os.Stderr.Fd())) {
		pr.p = mpb.New(mpb.WithOutput(os.Stderr), mpb.WithWidth(64))
	}
	return pr
}

// events adapts the progress renderer to transfer callbacks.
func (pr *progress) events() transfer.Events {
	return transfer.Events{
		OnBlobStart: func(desc ocispec.Descriptor, resumeOffset int64) func(int64) {
			if pr.p == nil {
				return nil
			}
			name := desc.Digest.Encoded()[:12]
			if resumeOffset > 0 {
				name += " (resumed)"
			}
			bar := pr.p.New(desc.Size,
				mpb.BarStyle().Rbound("|"),
				mpb.PrependDecorators(
					decor.Name(name, decor.WC{W: len(name) + 1, C: decor.DindentRight}),
					decor.CountersKibiByte("% .1f / % .1f"),
				),
				mpb.AppendDecorators(decor.Percentage()),
			)
			if resumeOffset > 0 {
				bar.SetCurrent(resumeOffset)
			}
			pr.mu.Lock()
			pr.bars = append(pr.bars, bar)
			pr.mu.Unlock()
			return bar.IncrInt64
		},
		OnBlobSkip: func(ocispec.Descriptor) {
			pr.skipped.Add(1)
		},
		OnSignature: func(stored bool, problem error) {
			pr.signed.Store(stored)
			if problem != nil {
				pr.mu.Lock()
				pr.sigProblem = problem
				pr.mu.Unlock()
			}
		},
		OnAttestation: func(stored bool, problem error) {
			pr.attested.Store(stored)
			if problem != nil {
				pr.mu.Lock()
				pr.attProblem = problem
				pr.mu.Unlock()
			}
		},
		OnBundle: func(stored bool, problem error) {
			pr.bundled.Store(stored)
			if problem != nil {
				pr.mu.Lock()
				pr.bundleProblem = problem
				pr.mu.Unlock()
			}
		},
	}
}

// close finishes rendering. On error, incomplete bars are aborted so the
// renderer does not block waiting for them to fill.
func (pr *progress) close(err error) {
	if pr.p == nil {
		return
	}
	if err != nil {
		pr.mu.Lock()
		for _, b := range pr.bars {
			b.Abort(true)
		}
		pr.mu.Unlock()
	}
	pr.p.Wait()
}

// report prints a post-transfer summary: content skipped as already present,
// and whether a signature came along, which decides whether this copy can be
// verified later without reaching the registry again.
func (pr *progress) report() {
	if n := pr.skipped.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "%d blob(s) already present, skipped\n", n)
	}
	if pr.signed.Load() {
		fmt.Fprintln(os.Stderr, "Signature stored alongside the model")
	}
	if pr.attested.Load() {
		fmt.Fprintln(os.Stderr, "Source attestation stored alongside the model")
	}
	if pr.bundled.Load() {
		fmt.Fprintln(os.Stderr, "Keyless signature stored alongside the model")
	}
	pr.mu.Lock()
	problem, attProblem, bundleProblem := pr.sigProblem, pr.attProblem, pr.bundleProblem
	pr.mu.Unlock()
	if problem != nil {
		// The transfer stands; only offline verification is affected.
		fmt.Fprintf(os.Stderr, "Warning: no signature stored (%v)\n", problem)
	}
	if attProblem != nil {
		// Likewise: the model is here, its provenance record is not.
		fmt.Fprintf(os.Stderr, "Warning: no source attestation stored (%v)\n", attProblem)
	}
	if bundleProblem != nil {
		// Likewise again, and it costs more: a keyless signature is the
		// only material an offline host can check one with.
		fmt.Fprintf(os.Stderr, "Warning: no keyless signature stored (%v)\n", bundleProblem)
	}
}
