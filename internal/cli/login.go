// Copyright The moci Authors
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"golang.org/x/term"

	"github.com/aimd54/moci/internal/transfer"
)

func newLoginCmd(v *viper.Viper) *cobra.Command {
	var username string
	var passwordStdin bool

	cmd := &cobra.Command{
		Use:   "login REGISTRY",
		Short: "Log in to a registry",
		Long: `Login validates credentials against the registry and saves them in the
Docker credentials store (a configured credential helper, or
~/.docker/config.json otherwise).`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			host := args[0]

			user := username
			if user == "" {
				fmt.Fprint(os.Stderr, "Username: ")
				r := bufio.NewReader(cmd.InOrStdin())
				line, err := r.ReadString('\n')
				if err != nil && line == "" {
					return fmt.Errorf("reading username: %w", err)
				}
				user = strings.TrimSpace(line)
			}

			var pass string
			switch {
			case passwordStdin:
				b, err := io.ReadAll(cmd.InOrStdin())
				if err != nil {
					return fmt.Errorf("reading password from stdin: %w", err)
				}
				pass = strings.TrimRight(string(b), "\r\n")
			case term.IsTerminal(int(os.Stdin.Fd())):
				fmt.Fprint(os.Stderr, "Password: ")
				b, err := term.ReadPassword(int(os.Stdin.Fd()))
				fmt.Fprintln(os.Stderr)
				if err != nil {
					return fmt.Errorf("reading password: %w", err)
				}
				pass = string(b)
			default:
				return fmt.Errorf("no terminal available; pass the password via --password-stdin")
			}

			client, err := newTransferClient(v)
			if err != nil {
				return err
			}
			if err := client.Login(ctx, host, user, pass); err != nil {
				return fmt.Errorf("login to %s failed: %w", host, err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Login to %s succeeded\n", host)
			return nil
		},
	}
	cmd.Flags().StringVarP(&username, "username", "u", "", "registry username")
	cmd.Flags().BoolVar(&passwordStdin, "password-stdin", false, "read the password from stdin")
	return cmd
}

func newLogoutCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "logout REGISTRY",
		Short: "Remove stored credentials for a registry",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := transfer.Logout(cmd.Context(), args[0]); err != nil {
				return err
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Logged out of %s\n", args[0])
			return nil
		},
	}
}
