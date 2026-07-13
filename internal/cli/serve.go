// Copyright The moci Authors
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

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/promhttp"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/moci/internal/refname"
	"github.com/aimd54/moci/internal/router"
	mociruntime "github.com/aimd54/moci/internal/runtime"
	"github.com/aimd54/moci/internal/store"
	"github.com/aimd54/moci/pkg/modelspec"
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
// conservative (design §15).
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
	)

	cmd := &cobra.Command{
		Use:   "serve [REF...]",
		Short: "Serve local models behind one OpenAI-compatible endpoint",
		Long: `Serve exposes /v1/chat/completions, /v1/completions, /v1/embeddings, and
/v1/models for all local models (or only the given REFs) and routes by the
request's "model" field. Models load lazily on first use, unload after
--idle-timeout, and are evicted least-recently-used when the memory budget
fills up. Prometheus metrics are on /metrics.`,
		Args: cobra.ArbitraryArgs,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}

			// Resolve the runtime once: every model uses the same binary.
			if runtimeRef == "" {
				runtimeRef = v.GetString(keyRuntimeRef)
			}
			bin, err := mociruntime.Resolve(ctx, st, runtimeRef)
			if err != nil {
				return err
			}

			// Validate explicit refs up front (fail fast, not on request).
			refs := make([]string, 0, len(args))
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
					st:     st,
					bin:    bin,
					refs:   refs,
					logDir: filepath.Join(st.Root(), "state", "logs"),
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
			fmt.Fprintf(cmd.OutOrStdout(), "moci serve listening on %s (runtime: %s)\n", addr, bin)

			select {
			case err := <-errCh:
				return err
			case <-ctx.Done():
				fmt.Fprintln(cmd.ErrOrStderr(), "shutting down…")
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
	must(v.BindPFlag(keyServeAddr, cmd.Flags().Lookup("addr")))
	must(v.BindPFlag(keyServeIdleTimeout, cmd.Flags().Lookup("idle-timeout")))
	must(v.BindPFlag(keyServeBudget, cmd.Flags().Lookup("memory-budget")))
	return cmd
}

// storeBackend adapts the local store to the router's Backend interface.
type storeBackend struct {
	st     *store.Store
	bin    string
	refs   []string // non-empty restricts the served set
	logDir string
}

func (b *storeBackend) List(ctx context.Context) ([]string, error) {
	if len(b.refs) > 0 {
		return b.refs, nil
	}
	entries, err := b.st.List(ctx)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		manifest, err := store.FetchManifest(ctx, b.st.OCI(), e.Descriptor)
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

func (b *storeBackend) Spec(ctx context.Context, ref string) (mociruntime.Spec, int64, error) {
	if len(b.refs) > 0 {
		allowed := false
		for _, r := range b.refs {
			if r == ref {
				allowed = true
				break
			}
		}
		if !allowed {
			return mociruntime.Spec{}, 0, errors.New("not among the served references")
		}
	}
	desc, err := b.st.Resolve(ctx, ref)
	if err != nil {
		return mociruntime.Spec{}, 0, err
	}
	info, err := loadModelInfo(ctx, b.st, ref, desc)
	if err != nil {
		return mociruntime.Spec{}, 0, err
	}
	fi, err := os.Stat(info.blobPath)
	if err != nil {
		return mociruntime.Spec{}, 0, err
	}
	memory := int64(float64(fi.Size())*memoryFactor) + memoryOverhead
	return mociruntime.Spec{
		Bin:       b.bin,
		ModelPath: info.blobPath,
		Alias:     ref,
		CtxSize:   info.defaults.Ctx,
		NGL:       info.defaults.NGL,
		ExtraArgs: info.defaults.Flags,
		LogDir:    b.logDir,
	}, memory, nil
}
