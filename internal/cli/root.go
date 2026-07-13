// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the moci command surface.
package cli

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	"github.com/aimd54/moci/internal/store"
	"github.com/aimd54/moci/internal/transfer"
	"github.com/aimd54/moci/internal/version"
)

// Config keys (config file ~/.config/moci/config.yaml, env prefix MOCI_).
const (
	keyRegistryDefault    = "registry.default"
	keyRegistryPlainHTTP  = "registry.plain-http"
	keyRegistryCAFile     = "registry.ca-file"
	keyRegistryInsecure   = "registry.insecure-skip-tls-verify"
	keyTransferConcurrent = "transfer.concurrency"
)

// New builds the root command with all subcommands attached.
func New() *cobra.Command {
	v := viper.New()

	root := &cobra.Command{
		Use:           "moci",
		Short:         "Distribute and serve GGUF models as OCI artifacts",
		Long:          "moci pulls, pushes, packs, and serves GGUF models as CNCF ModelPack artifacts\nagainst any OCI 1.1 registry — daemonless, in one binary.",
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return initConfig(v, cmd)
		},
	}

	pf := root.PersistentFlags()
	pf.String("config", "", "config file (default ~/.config/moci/config.yaml)")
	pf.String("registry", "", "default registry host applied to short references")
	pf.Bool("plain-http", false, "use HTTP instead of HTTPS for registries")
	pf.String("ca-file", "", "PEM CA bundle to trust in addition to the system pool")
	pf.Bool("insecure-skip-tls-verify", false, "skip TLS certificate verification (dangerous; lab bring-up only)")
	pf.Int("concurrency", transfer.DefaultConcurrency, "parallel blob streams for transfers")
	pf.Bool("quiet", false, "suppress progress output")

	must(v.BindPFlag(keyRegistryDefault, pf.Lookup("registry")))
	must(v.BindPFlag(keyRegistryPlainHTTP, pf.Lookup("plain-http")))
	must(v.BindPFlag(keyRegistryCAFile, pf.Lookup("ca-file")))
	must(v.BindPFlag(keyRegistryInsecure, pf.Lookup("insecure-skip-tls-verify")))
	must(v.BindPFlag(keyTransferConcurrent, pf.Lookup("concurrency")))

	root.AddCommand(
		newPullCmd(v),
		newPushCmd(v),
		newPackCmd(v),
		newCpCmd(v),
		newSaveCmd(),
		newLoadCmd(),
		newLsCmd(v),
		newRmCmd(),
		newGCCmd(),
		newLoginCmd(v),
		newLogoutCmd(),
		newRuntimeCmd(v),
		newRunCmd(v),
		newServeCmd(v),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute(ctx context.Context) int {
	root := New()
	if err := root.ExecuteContext(ctx); err != nil {
		fmt.Fprintf(os.Stderr, "moci: %v\n", err)
		return 1
	}
	return 0
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// initConfig loads the config file (if any) and env overrides into v.
func initConfig(v *viper.Viper, cmd *cobra.Command) error {
	v.SetEnvPrefix("MOCI")
	v.SetEnvKeyReplacer(strings.NewReplacer(".", "_", "-", "_"))
	v.AutomaticEnv()

	cfgFile, err := cmd.Flags().GetString("config")
	if err != nil {
		return err
	}
	if cfgFile != "" {
		v.SetConfigFile(cfgFile)
		if err := v.ReadInConfig(); err != nil {
			return fmt.Errorf("reading config %s: %w", cfgFile, err)
		}
		return nil
	}

	confDir, err := os.UserConfigDir()
	if err != nil {
		return nil // no config dir: flags/env only
	}
	v.SetConfigFile(filepath.Join(confDir, "moci", "config.yaml"))
	if err := v.ReadInConfig(); err != nil {
		if os.IsNotExist(err) {
			return nil
		}
		return fmt.Errorf("reading config %s: %w", v.ConfigFileUsed(), err)
	}
	return nil
}

// newTransferClient builds the transfer client from resolved config.
func newTransferClient(v *viper.Viper) (*transfer.Client, error) {
	if v.GetBool(keyRegistryInsecure) {
		fmt.Fprintln(os.Stderr, "WARNING: TLS certificate verification is DISABLED (--insecure-skip-tls-verify). Do not use outside lab bring-up.")
	}
	return transfer.New(transfer.Options{
		PlainHTTP:             v.GetBool(keyRegistryPlainHTTP),
		InsecureSkipTLSVerify: v.GetBool(keyRegistryInsecure),
		CAFile:                v.GetString(keyRegistryCAFile),
		UserAgent:             "moci/" + version.Version(),
		Concurrency:           v.GetInt(keyTransferConcurrent),
	})
}

// openStore opens the local store.
func openStore(ctx context.Context) (*store.Store, error) {
	return store.Open(ctx, "")
}
