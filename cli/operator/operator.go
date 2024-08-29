package operator

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/operator"
)

func init() {
	cli_utils.SetOperatorFlags(StartDKGOperator)
}

var StartDKGOperator = &cobra.Command{
	Use:   "start-operator",
	Short: "Starts an instance of DKG operator",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		██████╗ ██╗  ██╗ ██████╗      ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindOperatorFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-operator")
		if err != nil {
			return err
		}
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Operator`s", zap.String("Version", cmd.Version))
		logger.Info("🔑 opening operator RSA private key file")
		privateKey, err := cli_utils.OpenPrivateKey(cli_utils.PrivKeyPassword, cli_utils.PrivKey)
		if err != nil {
			logger.Fatal("😥 Failed to load private key: ", zap.Error(err))
		}
		srv, err := operator.New(privateKey, logger, []byte(cmd.Version), cli_utils.OperatorID, cli_utils.OutputPath, cli_utils.EthEndpointURL)
		if err != nil {
			logger.Fatal("😥 Failed to create new operator instance: ", zap.Error(err))
		}
		logger.Info("🚀 Starting DKG operator", zap.Uint64("at port", cli_utils.Port))
		if err := srv.Start(uint16(cli_utils.Port), cli_utils.ServerTLSCertPath, cli_utils.ServerTLSKeyPath); err != nil {
			log.Fatalf("Error in operator %v", err)
		}
		return nil
	},
}
