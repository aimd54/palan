// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"fmt"
	"runtime"
	"text/tabwriter"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/moci/internal/refname"
	mociruntime "github.com/aimd54/moci/internal/runtime"
	"github.com/aimd54/moci/internal/store"
)

func newRuntimeCmd(v *viper.Viper) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "runtime",
		Short: "Manage inference runtimes distributed as OCI artifacts",
		Long: `Runtimes are version-pinned llama-server builds distributed through the
same registries as the models (conventionally under runtimes/), so air-gapped
hosts receive inference engines through the already-established channel.`,
	}
	cmd.AddCommand(newRuntimePullCmd(v), newRuntimeLsCmd(), newRuntimePackCmd(v))
	return cmd
}

func newRuntimePullCmd(v *viper.Viper) *cobra.Command {
	return &cobra.Command{
		Use:   "pull REF",
		Short: "Pull a runtime artifact and materialize its executable",
		Args:  cobra.ExactArgs(1),
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
			pr := newProgress(v.GetBool("quiet"))
			_, err = client.Pull(ctx, st, ref, pr.events())
			pr.close(err)
			if err != nil {
				return err
			}
			entry, err := mociruntime.Ensure(ctx, st, ref.String())
			if err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Runtime ready: %s\n", entry)
			fmt.Fprintf(cmd.OutOrStdout(), "Set runtime.ref: %q in the config to use it by default.\n", ref.String())
			return nil
		},
	}
}

func newRuntimeLsCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List runtime artifacts in the local store",
		Args:  cobra.NoArgs,
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

			entries, err := mociruntime.List(ctx, st)
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
				cfg, err := store.FetchJSON[mociruntime.Config](ctx, st.OCI(), manifest.Config)
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
		Long: `Pack stores runtime files (the llama-server binary plus any shared
libraries) as an OCI artifact. The publisher-side counterpart of
'runtime pull'.`,
		Args: cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			ref, err := refname.Parse(tag, v.GetString(keyRegistryDefault))
			if err != nil {
				return err
			}
			files := make([]mociruntime.PackFile, 0, len(args))
			for _, p := range args {
				files = append(files, mociruntime.PackFile{Path: p})
			}
			cfg := mociruntime.Config{
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

			desc, err := mociruntime.Pack(ctx, st, files, cfg, ref.String())
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
	cmd.Flags().StringVar(&flavor, "flavor", "cpu", "acceleration flavor: cpu|cuda12|metal|vulkan…")
	cmd.Flags().StringVar(&entrypoint, "entrypoint", "llama-server", "executable file name among the packed files")
	cmd.Flags().StringVar(&osName, "os", runtime.GOOS, "target OS (GOOS)")
	cmd.Flags().StringVar(&arch, "arch", runtime.GOARCH, "target architecture (GOARCH)")
	cmd.Flags().BoolVar(&doPush, "push", false, "push to the registry after packing")
	must(cmd.MarkFlagRequired("tag"))
	must(cmd.MarkFlagRequired("build"))
	return cmd
}
