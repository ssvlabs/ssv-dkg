package cli

import (
	"log"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/cli/initiator"
	"github.com/bloxapp/ssv-dkg/cli/operator"
	"github.com/bloxapp/ssv-dkg/cli/verify"
)

func init() {
	RootCmd.AddCommand(initiator.StartDKG)
	RootCmd.AddCommand(operator.StartDKGOperator)
	RootCmd.AddCommand(initiator.HealthCheck)
	RootCmd.AddCommand(verify.Verify)
	RootCmd.AddCommand(initiator.StartResigning)
	RootCmd.AddCommand(initiator.StartReshare)
}

// RootCmd represents the root command of DKG-tool CLI
var RootCmd = &cobra.Command{
	Use:   "ssv-dkg",
	Short: "CLI for running Distributed Key Generation protocol",
	PersistentPreRun: func(cmd *cobra.Command, args []string) {
	},
}

// Execute executes the root command
func Execute(appName, version string) {
	RootCmd.Short = appName
	RootCmd.Version = version
	initiator.HealthCheck.Version = version
	initiator.StartDKG.Version = version
	initiator.StartResigning.Version = version
	initiator.StartReshare.Version = version
	operator.StartDKGOperator.Version = version
	if err := RootCmd.Execute(); err != nil {
		log.Fatal("failed to execute root command", zap.Error(err))
	}
}
