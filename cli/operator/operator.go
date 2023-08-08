package operator

import (
	"log"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

var StartDKGServer = &cobra.Command{
	Use:   "start-dkg-server",
	Short: "Starts an instance of DKG",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logging.SetGlobalLogger("debug", "capital", "console"); err != nil {
			log.Fatal(err)
		}
		logger := zap.L().Named(cmd.Short)
		privKeyPath, err := flags.GetOperatorPrivateKeyFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get operator private key flag value", zap.Error(err))
		}
		// Load and decode the private key
		// TODO: consider adding secure keystore and provide password instead of plain text priv key
		privateKey, err := load.PrivateKey(privKeyPath)
		if err != nil {
			log.Fatalf("Failed to load private key: %v", err)
		}

		srv := server.New(privateKey)

		port, err := flags.GetOperatorPortFlagValue(cmd)
		if err != nil {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		logger.Info("Starting DKG instance at", zap.Uint64("port", port))
		if err := srv.Start(uint16(port)); err != nil {
			log.Fatalf("Error in server %v", err)
		}
	},
}

func init() {
	flags.OperatorPrivateKeyFlag(StartDKGServer)
	flags.OperatorPortFlag(StartDKGServer)
}
