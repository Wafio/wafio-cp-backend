package main

import (
	"github.com/spf13/cobra"
)

var rootCmd = &cobra.Command{
	Use:   "wafio",
	Short: "WAFio control plane: HTTP API, agent gRPC, per-project WAF config",
}

func init() {
	rootCmd.AddCommand(serveCmd)
	rootCmd.AddCommand(migrateCmd)
	rootCmd.AddCommand(fetchDataCmd)
}
