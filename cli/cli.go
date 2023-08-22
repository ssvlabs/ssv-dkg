package cli

import (
	"log"

	"github.com/bloxapp/ssv-dkg-tool/cli/initiator"
	"github.com/bloxapp/ssv-dkg-tool/cli/operator"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

// RootCmd represents the root command of DKG-tool CLI
var RootCmd = &cobra.Command{
	Use:   "dkgcli",
	Short: "CLI for running Distributed Key Generation protocol",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
}

// Execute executes the root command
func Execute(appName, version string) {
	RootCmd.Short = appName
	RootCmd.Version = version

	if err := RootCmd.Execute(); err != nil {
		log.Fatal("failed to execute root command", zap.Error(err))
	}
}

func init() {
	RootCmd.AddCommand(initiator.StartDKG)
	RootCmd.AddCommand(operator.StartDKGServer)
}
