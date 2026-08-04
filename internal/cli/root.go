// Copyright The palan Authors
// SPDX-License-Identifier: Apache-2.0

// Package cli implements the palan command surface.
package cli

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"syscall"

	"github.com/charmbracelet/fang"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/aimd54/palan/internal/store"
	"github.com/aimd54/palan/internal/transfer"
	"github.com/aimd54/palan/internal/ui"
	"github.com/aimd54/palan/internal/version"
)

// Config keys (config file ~/.config/palan/config.yaml, env prefix PALAN_).
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
		Use:   "palan",
		Short: "Distribute and serve GGUF models as OCI artifacts",
		Long:  "palan pulls, pushes, packs, and serves GGUF models as CNCF ModelPack artifacts\nagainst any OCI 1.1 registry. Daemonless, in one binary.",
		Example: `  # Pack a GGUF as an OCI artifact and push it
  palan pack qwen3-8b-q4.gguf -t registry.internal/llm/qwen3:8b-q4 --push

  # Pull it anywhere and chat with it
  palan pull registry.internal/llm/qwen3:8b-q4
  palan run  registry.internal/llm/qwen3:8b-q4

  # Or serve every local model behind one OpenAI-compatible endpoint
  palan serve`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			// Before any command writes anything, so no output escapes the
			// decision the user made on the command line.
			if noColor, err := cmd.Flags().GetBool("no-color"); err == nil {
				ui.SetNoColor(noColor)
			}
			return initConfig(v, cmd)
		},
	}

	pf := root.PersistentFlags()
	pf.String("config", "", "config file (default ~/.config/palan/config.yaml)")
	pf.String("registry", "", "default registry host applied to short references")
	pf.Bool("plain-http", false, "use HTTP instead of HTTPS for registries")
	pf.String("ca-file", "", "PEM CA bundle to trust in addition to the system pool")
	pf.Bool("insecure-skip-tls-verify", false, "skip TLS certificate verification (dangerous; lab bring-up only)")
	pf.Int("concurrency", transfer.DefaultConcurrency, "parallel blob streams for transfers")
	pf.Bool("quiet", false, "suppress progress output")
	pf.Bool("no-color", false, "disable colour output (NO_COLOR is honoured too)")

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
		newLoadCmd(v),
		newLsCmd(v),
		newDescribeCmd(v),
		newRmCmd(v),
		newGCCmd(),
		newLoginCmd(v),
		newLogoutCmd(),
		newSignCmd(v),
		newVerifyCmd(v),
		newRuntimeCmd(v),
		newRunCmd(v),
		newServeCmd(v),
		newVersionCmd(),
	)
	return root
}

// Execute runs the CLI and returns a process exit code.
func Execute(ctx context.Context) int {
	// Help and error rendering happen outside any command's PersistentPreRunE,
	// so --no-color has to be seen before cobra parses anything. NO_COLOR is
	// the one signal both this package and the help renderer already read.
	for _, a := range os.Args[1:] {
		if a == "--no-color" {
			must(os.Setenv("NO_COLOR", "1"))
			break
		}
		if a == "--" {
			break
		}
	}

	root := New()
	err := fang.Execute(ctx, root,
		fang.WithVersion(version.Version()),
		fang.WithErrorHandler(errorHandler),
		fang.WithNotifySignal(os.Interrupt, syscall.SIGTERM),
	)
	if err != nil {
		return 1
	}
	return 0
}

// errorHandler keeps failures readable at a terminal without changing what a
// script reads. Plain stderr keeps the "palan: " prefix it has always had,
// because that is output something may already be matching on; a terminal
// gets the styled form.
func errorHandler(w io.Writer, styles fang.Styles, err error) {
	if f, ok := w.(*os.File); ok && term.IsTerminal(int(f.Fd())) {
		fang.DefaultErrorHandler(w, styles, err)
		return
	}
	fmt.Fprintf(w, "palan: %v\n", err)
}

func must(err error) {
	if err != nil {
		panic(err)
	}
}

// initConfig loads the config file (if any) and env overrides into v.
func initConfig(v *viper.Viper, cmd *cobra.Command) error {
	v.SetEnvPrefix("PALAN")
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
	v.SetConfigFile(filepath.Join(confDir, "palan", "config.yaml"))
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
		UserAgent:             "palan/" + version.Version(),
		Concurrency:           v.GetInt(keyTransferConcurrent),
	})
}

// openStore opens the local store.
func openStore(ctx context.Context) (*store.Store, error) {
	return store.Open(ctx, "")
}
