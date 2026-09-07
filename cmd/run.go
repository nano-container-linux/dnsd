package cmd

import (
	"dnsd/server"

	"github.com/spf13/cobra"
)

func init() {
	var configDir string

	runCmd := &cobra.Command{
		Use:   "run",
		Short: "Run DNS server",
		RunE: func(cmd *cobra.Command, args []string) error {
			return server.Run(configDir)
		},
	}

	runCmd.Flags().StringVar(&configDir, "config-dir", ".", "Directory containing .hcl config files")
	rootCmd.AddCommand(runCmd)
}
