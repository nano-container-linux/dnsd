package cmd

import "github.com/spf13/cobra"

var rootCmd = &cobra.Command{
	Use:   "dnsd",
	Short: "dnsd server",
}

func Execute() error {
	return rootCmd.Execute()
}
