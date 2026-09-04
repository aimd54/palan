// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"fmt"
	"io"
	"runtime"
	"text/tabwriter"

	ocispec "github.com/opencontainers/image-spec/specs-go/v1"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/palan/internal/refname"
	palanruntime "github.com/aimd54/palan/internal/runtime"
	"github.com/aimd54/palan/internal/store"
)

func newRuntimeCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Manage inference runtimes distributed as OCI artifacts",
		Example: `  # Runtimes travel the same way models do
  palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12
  palan runtime ls`,
		Long: `Runtimes are version-pinned llama-server builds distributed through the
same registries as the models (conventionally under runtimes/), so air-gapped
hosts receive inference engines through the already-established channel.`,
	}
	cmd.AddCommand(newRuntimePullCmd(v), newRuntimeLsCmd(), newRuntimePackCmd(v))
	return cmd
}

func newRuntimePullCmd(v *viper.Viper) *cobra.Command {
	var (
		doVerify  bool
		verifyKey string
	)
	cmd := &cobra.Command{
		Use:   "pull REF",
		Short: "Pull a runtime artifact and materialize its executable",
		Example: `  # Fetch a llama-server build and unpack it ready to run
  palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12

  # Refuse the build unless it carries a valid signature
  palan runtime pull registry.internal/runtimes/llama-server:b4567-cuda12 --verify`,
		Long: `Pull fetches a runtime artifact and unpacks its executable ready to run.

A runtime is an engine that will read the weights, so it is signed and
verified the way a model is. With --verify, or with verify.required set in
the config, the signature is checked on the registry before anything is
downloaded, and the trust policy decides who may sign it.`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(args[0], v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.Lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			client, err := newTransferClient(v)
			if err != nil {
				return err
			}
			// Checked against the registry before anything is downloaded,
			// so an unsigned engine build is refused rather than fetched
			// and then rejected.
			if doVerify || v.GetBool(keyVerifyRequired) {
				repo, rerr := client.Repository(ref)
				if rerr != nil {
					return rerr
				}
				desc, rerr := repo.Resolve(ctx, ref.Reference)
				if rerr != nil {
					return rerr
				}
				if _, rerr = verifyDigest(ctx, v, verifyKey, remoteSource(repo, desc, "registry"), ref); rerr != nil {
					return rerr
				}
				fmt.Fprintf(cmd.ErrOrStderr(), "Signature verified for %s@%s\n", ref, desc.Digest)
			}
			pr := newProgress(v.GetBool("quiet"))
			_, err = client.Pull(ctx, st, ref, pr.events())
			pr.close(err)
			if err != nil {
				return err
			}
			entry, err := palanruntime.Ensure(ctx, st, ref.String())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Runtime ready: %s\n", entry)
			fmt.Fprintf(cmd.OutOrStdout(), "Set runtime.ref: %q in the config to use it by default.\n", ref.String())
			return nil
		},
	}
	cmd.Flags().BoolVar(&doVerify, "verify", false, "require a valid signature on the runtime before downloading it")
	cmd.Flags().StringVar(&verifyKey, "verify-key", "", "public key for --verify (default: verify.key from the config)")
	return cmd
}

// checkRuntime holds an engine build to the same policy as a model before it
// is unpacked and spawned, and returns the reference to load.
//
// A runtime artifact is the executable that will read the weights, so a host
// checking its models and not its engine has checked the smaller half. It
// travels the same channel and is checked the same way.
//
// The reference is parsed here and handed back, so the artifact that was
// checked and the artifact that is loaded are named identically. Resolving
// the raw string separately would let a reference that needed a default
// registry or a default tag be verified under one name and loaded under
// another.
//
// An empty reference means no runtime artifact is configured and
// llama-server comes from PATH. That binary arrived by some other route and
// there is nothing here to hold it to, which is said rather than passed
// over: silence would read the same as a runtime that was checked.
func checkRuntime(
	ctx context.Context, w io.Writer, v *viper.Viper, st *store.Store,
	gate func(context.Context, string) (ocispec.Descriptor, error),
	ref string, rehash bool,
) (string, error) {
	if gate == nil {
		return ref, nil
	}
	if ref == "" {
		fmt.Fprintln(w, "Verification is required and no runtime artifact is configured, "+
			"so llama-server is taken from PATH and palan cannot say where that build came from. "+
			"Set runtime.ref to a signed runtime artifact to bring it under the same policy.")
		return ref, nil
	}
	parsed, err := refname.Parse(ref, v.GetString(keyRegistryDefault))
	if err != nil {
		return "", err
	}
	name := parsed.String()
	// Absence is reported before the signature is checked, so a host that
	// simply has not pulled the runtime is told that rather than sent to
	// the registry to verify something it does not hold.
	local, err := st.Resolve(ctx, name)
	if err != nil {
		return "", fmt.Errorf("runtime %q not in local store (try `palan runtime pull`): %w", name, err)
	}
	verified, err := gate(ctx, name)
	if err != nil {
		return "", err
	}
	if err := checkLoadedContent(ctx, st, name, local, verified, rehash); err != nil {
		return "", err
	}
	return name, nil
}

func newRuntimeLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List runtime artifacts in the local store",
		Example: `  # Runtimes held locally, with their build identifiers
  palan runtime ls`,
		Args: cobra.NoArgs,
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx := cmd.Context()
			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.RLock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			entries, err := palanruntime.List(ctx, st)
			if err != nil {
				return err
			}
			tw := tabwriter.NewWriter(cmd.OutOrStdout(), 2, 4, 2, ' ', 0)
			fmt.Fprintln(tw, "REF\tNAME\tBUILD\tFLAVOR\tOS/ARCH")
			for _, e := range entries {
				manifest, err := store.FetchManifest(ctx, st.OCI(), e.Descriptor)
				if err != nil {
					continue
				}
				cfg, err := store.FetchJSON[palanruntime.Config](ctx, st.OCI(), manifest.Config)
				if err != nil {
					continue
				}
				fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s/%s\n", e.Ref, cfg.Name, cfg.Build, cfg.Flavor, cfg.OS, cfg.Arch)
			}
			return tw.Flush()
		},
	}
}

func newRuntimePackCmd(v *viper.Viper) *cobra.Command {
	var (
		tag        string
		name       string
		build      string
		flavor     string
		entrypoint string
		osName     string
		arch       string
		doPush     bool
	)
	cmd := &cobra.Command{
		Use:   "pack PATH... -t REF --build BUILD",
		Short: "Pack a llama-server build as a runtime artifact",
		Example: `  # Pack a build with the shared libraries it loads at run time
  palan runtime pack llama-server lib*.so -t runtimes/llama-server:b4567-cuda12 --build b4567`,
		Long: `Pack stores runtime files (the llama-server binary plus any shared
libraries) as an OCI artifact. The publisher-side counterpart of
'runtime pull'.

Libraries packed beside the executable are found when it runs: palan points
the dynamic loader at the unpacked directory, so a build carrying no $ORIGIN
runpath still resolves its own libraries instead of the host's. Include every
library the binary needs, because the host serving the model may have none of
them installed.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(tag, v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			files := make([]palanruntime.PackFile, 0, len(args))
			for _, p := range args {
				files = append(files, palanruntime.PackFile{Path: p})
			}
			cfg := palanruntime.Config{
				Name: name, Build: build, OS: osName, Arch: arch,
				Flavor: flavor, Entrypoint: entrypoint,
			}

			st, err := openStore(ctx)
			if err != nil {
				return err
			}
			unlock, err := st.Lock(ctx)
			if err != nil {
				return err
			}
			defer unlock()

			desc, err := palanruntime.Pack(ctx, st, files, cfg, ref.String())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Packed %s\nDigest: %s\n", ref, desc.Digest)

			if doPush {
				client, err := newTransferClient(v)
				if err != nil {
					return err
				}
				pr := newProgress(v.GetBool("quiet"))
				_, err = client.Push(ctx, st, ref, pr.events())
				pr.close(err)
				if err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "Pushed %s\n", ref)
			}
			return nil
		},
	}
	cmd.Flags().StringVarP(&tag, "tag", "t", "", "reference to tag the runtime with (required)")
	cmd.Flags().StringVar(&name, "name", "llama-server", "runtime name")
	cmd.Flags().StringVar(&build, "build", "", "upstream build identifier, e.g. b4567 (required)")
	cmd.Flags().StringVar(&flavor, "flavor", "cpu", "acceleration flavor: cpu|cuda12|metal|vulkan...")
	cmd.Flags().StringVar(&entrypoint, "entrypoint", "llama-server", "executable file name among the packed files")
	cmd.Flags().StringVar(&osName, "os", runtime.GOOS, "target OS (GOOS)")
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "target architecture (GOARCH)")
	cmd.Flags().BoolVar(&doPush, "push", false, "push to the registry after packing")
	must(cmd.MarkFlagRequired("tag"))
	must(cmd.MarkFlagRequired("build"))
	return cmd
}
