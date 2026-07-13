// Copyright The moci Authors
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

	"github.com/aimd54/moci/internal/transfer"
)

// progress renders per-blob transfer bars on stderr when attached to a
// terminal; otherwise it stays silent (blob counts only).
type progress struct {
	p       *mpb.Progress
	mu      sync.Mutex
	bars    []*mpb.Bar
	skipped atomic.Int64
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

// report prints a post-transfer summary line for skipped content.
func (pr *progress) report() {
	if n := pr.skipped.Load(); n > 0 {
		fmt.Fprintf(os.Stderr, "%d blob(s) already present, skipped\n", n)
	}
}
