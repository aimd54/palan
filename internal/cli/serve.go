// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"time"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	"github.com/aimd54/palan/internal/router"
	palanruntime "github.com/aimd54/palan/internal/runtime"
	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/pkg/modelspec"
)

// Config keys for serve.
const (
	keyServeAddr        = "serve.addr"
	keyServeIdleTimeout = "serve.idle-timeout"
	keyServeBudget      = "serve.memory-budget"
	keyServeBearerToken = "serve.bearer-token"
)

// memoryOverhead is the fixed per-model allowance added on top of the
// weight size (KV cache, activations); the multiplier keeps the estimate
// conservative.
const (
	memoryFactor   = 1.2
	memoryOverhead = 512 << 20
)

func newServeCmd(v *viper.Viper) *cobra.Command {
	var (
		addr       string
		idle       time.Duration
		budgetStr  string
		keepLoaded []string
		runtimeRef string
		doVerify   bool
		verifyKey  string
		doRehash   bool
	)

	cmd := &cobra.Command{
		Use:   "serve [REF...]",
		Short: "Serve local models behind one OpenAI-compatible endpoint",
		Example: `  # Serve every model in the store, loading each on first request
  palan serve

  # Keep one model resident and cap what may be loaded at once
  palan serve --keep-loaded llm/qwen3:8b-q4 --memory-budget 9GiB`,
		Long: `Serve exposes /v1/chat/completions, /v1/completions, /v1/embeddings, and
/v1/models for all local models (or only the given REFs) and routes by the
request's "model" field. Models load lazily on first use, unload after
--idle-timeout, and are evicted least-recently-used when the memory budget
fills up. Prometheus metrics are on /metrics.

GPU offload comes from the model, not from serve: --n-gpu-layers is passed
only when the model was packed with 'pack --ngl' (io.palan.serve.defaults).
Without it serve leaves the choice to the runtime, and a build that defaults
to no offload will serve from CPU on a GPU host.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			st, err := store.OpenDeferred("")
			if err != nil {
				return err
			}

			// Resolve the runtime once: every model uses the same binary.
			// It is held to the same policy as the weights it will read,
			// and by the same gate the models go through.
			gate := verifyGate(v, st, doVerify, verifyKey)
			rehash := rehashRequested(v, doRehash)
			if runtimeRef == "" {
				runtimeRef = v.GetString(keyRuntimeRef)
			}
			// Start-up reads the store under a shared lock, released before
			// serving begins, for the reason each load does.
			var bin string
			refs := make([]string, 0, len(args))
			err = withSharedLock(ctx, st, cmd.ErrOrStderr(), func() error {
				var runtimeDesc ocispec.Descriptor
				var err error
				runtimeRef, runtimeDesc, err = checkRuntime(ctx, cmd.ErrOrStderr(), v, st, gate, runtimeRef, rehash)
				if err != nil {
					return err
				}
				if bin, err = palanruntime.Resolve(ctx, st, runtimeRef, runtimeDesc); err != nil {
					return err
				}
				// Validate explicit refs up front (fail fast, not on request).
				for _, raw := range args {
					ref, err := refname.Parse(raw, v.GetString(keyRegistryDefault))
					if err != nil {
						return err
					}
					if _, err := st.Resolve(ctx, ref.String()); err != nil {
						return fmt.Errorf("%s is not in the local store (pull it first): %w", ref, err)
					}
					refs = append(refs, ref.String())
				}
				return nil
			})
			if err != nil {
				return err
			}

			budget := int64(0)
			if budgetStr != "" {
				if budget, err = router.ParseBudget(budgetStr); err != nil {
					return err
				}
			} else {
				var origin string
				budget, origin = router.DetectBudget()
				fmt.Fprintf(cmd.ErrOrStderr(), "Memory budget: %s (auto-detected from %s; override with --memory-budget)\n", humanBytes(budget), origin)
			}

			reg := prometheus.NewRegistry()
			rt, err := router.New(router.Options{
				Backend: &storeBackend{
					root:   st.Root(),
					bin:    bin,
					refs:   refs,
					logDir: filepath.Join(st.Root(), "state", "logs"),
					gateFor: func(s *store.Store) func(context.Context, string) (ocispec.Descriptor, error) {
						return verifyGate(v, s, doVerify, verifyKey)
					},
					rehash: rehash,
				},
				MemoryBudget: budget,
				IdleTimeout:  idle,
				BearerToken:  v.GetString(keyServeBearerToken),
				KeepLoaded:   keepLoaded,
				Metrics:      router.NewMetrics(reg),
			})
			if err != nil {
				return err
			}
			defer rt.Shutdown(context.Background())

			mux := http.NewServeMux()
			mux.Handle("/metrics", promhttp.HandlerFor(reg, promhttp.HandlerOpts{}))
			mux.Handle("/", rt)

			srv := &http.Server{Addr: addr, Handler: mux, ReadHeaderTimeout: 10 * time.Second}
			errCh := make(chan error, 1)
			go func() { errCh <- srv.ListenAndServe() }()
			fmt.Fprintf(cmd.OutOrStdout(), "palan serve listening on %s (runtime: %s)\n", addr, bin)

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				fmt.Fprintln(cmd.ErrOrStderr(), "shutting down...")
				shutCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
				defer cancel()
				_ = srv.Shutdown(shutCtx)
				return nil
			}
		},
	}
	cmd.Flags().StringVar(&addr, "addr", router.DefaultAddr, "listen address")
	cmd.Flags().DurationVar(&idle, "idle-timeout", router.DefaultIdleTimeout, "unload models idle longer than this")
	cmd.Flags().StringVar(&budgetStr, "memory-budget", "", "memory budget for loaded models, e.g. 9GiB (default: auto-detect)")
	cmd.Flags().StringSliceVar(&keepLoaded, "keep-loaded", nil, "refs never unloaded or evicted")
	cmd.Flags().StringVar(&runtimeRef, "runtime", "", "runtime artifact reference (default: runtime.ref config, then PATH)")
	cmd.Flags().BoolVar(&doVerify, "verify", false, "require a valid signature before loading any model")
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "public key for --verify (default: verify.key from the config)")
	cmd.Flags().BoolVar(&doRehash, "rehash", false, "read each model's blobs back at load and hold them to the digests its manifest records")
	must(v.BindPFlag(keyServeAddr, cmd.Flags().Lookup("addr")))
	must(v.BindPFlag(keyServeIdleTimeout, cmd.Flags().Lookup("idle-timeout")))
	must(v.BindPFlag(keyServeBudget, cmd.Flags().Lookup("memory-budget")))
	return cmd
}

// storeBackend adapts the local store to the router's Backend interface.
type storeBackend struct {
	// root is where the store lives. Each load and each listing opens it
	// afresh rather than sharing one Store across requests, because a
	// Store is not safe for concurrent use and serve is the one command
	// that would use it that way: two loads run at once, and the model
	// list is read alongside them. A store opened per load has its own
	// lock descriptor, so one load releasing never drops what another
	// still holds, and its own view of the layout, so nothing is swapped
	// underneath a load that is halfway through reading.
	root   string
	bin    string
	refs   []string // non-empty restricts the served set
	logDir string
	// gateFor builds the check that must accept a model before it is
	// loaded, for the store a load has just opened. It runs once per load
	// rather than once per request, and re-runs after an eviction, which
	// is the point: it re-reads a store that may have changed since the
	// model was imported. It answers with the artifact the signature
	// covered, which the copy on disk is then held against. Built per load
	// so that it reads the same store the load does, and nil when nothing
	// asked for verification.
	gateFor func(*store.Store) func(ctx context.Context, ref string) (ocispec.Descriptor, error)
	// rehash asks for the loaded model's blobs to be read back on every
	// load, closing the gap between a manifest that verifies and the bytes
	// beneath it. Off by default: it re-reads whole weight files.
	rehash bool
}

// open reads the store for one load, under a shared lock held until release
// is called.
//
// The lock is taken for the length of one load, not for the life of the
// process. serve runs for hours and an exclusive hold would block every pull
// for all of them, but a pull tags a model before it fetches the model's
// signature, so a load reading between the two finds the model and not the
// signature, and on a host with no registry refuses it. Taking the lock also
// reads the layout as it stands, so a model pulled since serve started is
// visible rather than a view from startup being served forever.
//
// A load waits for a pull, pack, import or collection in progress, and a
// wait the request gave up on is reported as the store being busy rather
// than the model being missing.
func (b *storeBackend) open(ctx context.Context) (*store.Store, func(), error) {
	st, release, err := store.OpenShared(ctx, b.root)
	if err != nil {
		if ctx.Err() != nil {
			return nil, nil, fmt.Errorf("%w: %w", router.ErrUnavailable, err)
		}
		return nil, nil, err
	}
	return st, release, nil
}

// List reads the store afresh on every call, so a model pulled since serve
// started is listed, and takes no lock. The list verifies nothing, so what
// a lock would buy it is a store at rest, and what it would cost is
// /v1/models answering nothing for as long as a pull runs, since a pull
// holds the store for its whole transfer.
func (b *storeBackend) List(ctx context.Context) ([]string, error) {
	if len(b.refs) > 0 {
		return b.refs, nil
	}
	st, err := store.Open(ctx, b.root)
	if err != nil {
		return nil, err
	}
	entries, err := st.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		manifest, err := store.FetchManifest(ctx, st.OCI(), e.Descriptor)
		if err != nil {
			continue
		}
		if manifest.ArtifactType == modelspec.ArtifactTypeModelManifest ||
			manifest.Config.MediaType == modelspec.MediaTypeModelConfig {
			out = append(out, e.Ref)
		}
	}
	return out, nil
}

func (b *storeBackend) Spec(ctx context.Context, ref string) (palanruntime.Spec, int64, error) {
	if len(b.refs) > 0 {
		allowed := false
		for _, r := range b.refs {
			if r == ref {
				allowed = true
				break
			}
		}
		if !allowed {
			return palanruntime.Spec{}, 0, errors.New("not among the served references")
		}
	}
	// One store, one lock and one view for the whole load, so the gate,
	// the comparison against the resident copy and the parse below all
	// describe the same artifact rather than three readings of a moving
	// one. The lock spans the gate, which can reach the registry, and the
	// re-read, which can stream every weight layer when it is asked for;
	// a pull on the same host waits that long, and that is the guarantee
	// being bought.
	st, release, err := b.open(ctx)
	if err != nil {
		return palanruntime.Spec{}, 0, err
	}
	defer release()
	var gate func(context.Context, string) (ocispec.Descriptor, error)
	if b.gateFor != nil {
		gate = b.gateFor(st)
	}

	var verified ocispec.Descriptor
	if gate != nil {
		if verified, err = gate(ctx, ref); err != nil {
			// Wrapped so the router answers 403: the model is present and
			// refused, which is a different answer from missing.
			return palanruntime.Spec{}, 0, fmt.Errorf("%w: %w", router.ErrUnverified, err)
		}
	}
	desc, err := st.Resolve(ctx, ref)
	if err != nil {
		return palanruntime.Spec{}, 0, err
	}
	// Held before loadModelInfo, which parses the artifact's own bytes: a
	// copy that is not the one that verified must be refused rather than
	// read. Re-reading the blobs is asked for on its own as well, so this
	// runs for it too rather than only behind a signature check.
	if gate != nil || b.rehash {
		if err := checkLoadedContent(ctx, st, ref, desc, verified, b.rehash); err != nil {
			return palanruntime.Spec{}, 0, fmt.Errorf("%w: %w", router.ErrUnverified, err)
		}
	}
	info, err := loadModelInfo(ctx, st, ref, desc)
	if err != nil {
		return palanruntime.Spec{}, 0, err
	}
	fi, err := os.Stat(info.blobPath)
	if err != nil {
		return palanruntime.Spec{}, 0, err
	}
	memory := int64(float64(fi.Size())*memoryFactor) + memoryOverhead
	return palanruntime.Spec{
		Bin:       b.bin,
		ModelPath: info.blobPath,
		Alias:     ref,
		CtxSize:   info.defaults.Ctx,
		NGL:       info.defaults.NGL,
		ExtraArgs: info.defaults.Flags,
		LogDir:    b.logDir,
	}, memory, nil
}
