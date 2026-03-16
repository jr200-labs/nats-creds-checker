package main

import (
	"fmt"
	"os"

	"github.com/spf13/cobra"

	"github.com/jr200/nats-creds-checker/internal/report"
	"github.com/jr200/nats-creds-checker/internal/validate"
)

var version = "dev"

func main() {
	rootCmd := &cobra.Command{
		Use:     "nats-creds-checker",
		Short:   "NATS credential validation and reporting tool",
		Version: version,
	}

	rootCmd.AddCommand(validateCmd())
	rootCmd.AddCommand(reportCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func validateCmd() *cobra.Command {
	var (
		credsFile   string
		credsB64Env string
		credsDir    string
		expect      []string
		expectFiles []string
	)

	cmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate NATS credentials exist and are well-formed (no network required)",
		RunE: func(cmd *cobra.Command, args []string) error {
			var checks []validate.Check

			if credsFile != "" {
				checks = append(checks, validate.CredsFileCheck(credsFile))
			}

			if credsB64Env != "" {
				checks = append(checks, validate.CredsB64EnvCheck(credsB64Env))
			}

			if credsDir != "" {
				checks = append(checks, validate.MultiFileCheck(credsDir, expect, expectFiles))
			}

			if len(checks) == 0 {
				return fmt.Errorf("at least one of --creds-file, --creds-b64-env, or --creds-dir must be specified")
			}

			return validate.RunAll(checks)
		},
	}

	cmd.Flags().StringVar(&credsFile, "creds-file", "", "Path to a .creds file to validate")
	cmd.Flags().StringVar(&credsB64Env, "creds-b64-env", "", "Name of env var containing base64-encoded .creds content")
	cmd.Flags().StringVar(&credsDir, "creds-dir", "", "Directory containing multiple credential files to validate")
	cmd.Flags().StringSliceVar(&expect, "expect", nil, "Comma-separated .creds files expected in --creds-dir (validated as NATS creds)")
	cmd.Flags().StringSliceVar(&expectFiles, "expect-files", nil, "Comma-separated files expected in --creds-dir (validated as non-empty)")

	return cmd
}

func reportCmd() *cobra.Command {
	var (
		monitorURL string
		credsFile  string
		tlsCA      string
	)

	cmd := &cobra.Command{
		Use:   "report",
		Short: "Report NATS credential status, account health, and connection info",
		RunE: func(cmd *cobra.Command, args []string) error {
			return report.Run(monitorURL, credsFile, tlsCA)
		},
	}

	cmd.Flags().StringVar(&monitorURL, "monitor-url", "", "NATS server monitor URL (e.g. http://localhost:8222)")
	cmd.Flags().StringVar(&credsFile, "creds", "", "Path to system account .creds file for server ping")
	cmd.Flags().StringVar(&tlsCA, "tls-ca", "", "Path to CA certificate for TLS verification")
	_ = cmd.MarkFlagRequired("monitor-url")

	return cmd
}
