package cmd

import (
	"dnsd/internal/dnsd"
	"fmt"

	"github.com/spf13/cobra"
)

func init() {
	var configDir string

	validateCmd := &cobra.Command{
		Use:   "validate",
		Short: "Validate DNS config files",
		RunE: func(cmd *cobra.Command, args []string) error {
			if err := dnsd.Validate(configDir); err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), "Configuration is valid")
			return nil
		},
	}

	validateCmd.Flags().StringVar(&configDir, "config-dir", ".", "Directory containing .hcl config files")
	rootCmd.AddCommand(validateCmd)
}
