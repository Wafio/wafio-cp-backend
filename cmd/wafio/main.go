// Command wafio: the WAFio control plane.
//
// Serves the HTTP management API and the static dashboard on server.http_addr
// (:9087) and the agent gRPC mTLS stream on server.agent_grpc_addr (:9090).
//
// Subcommands: serve, migrate (up/down/version/fresh), admin (create/list),
// fetch-data.
package main

import (
	"os"

	_ "github.com/wafio/wafio-cp-backend/shared/utctime" // pins time.Local to UTC
)

func main() {
	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}
