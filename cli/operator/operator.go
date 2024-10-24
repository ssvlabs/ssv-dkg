package operator

import (
	"fmt"
	"log"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/operator"
)

func init() {
	flags.SetOperatorFlags(StartDKGOperator)
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
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindOperatorFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-operator", flags.LogFilePath, flags.LogLevel, flags.LogFormat, flags.LogLevelFormat)
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
		privateKey, err := cli_utils.OpenPrivateKey(flags.PrivKeyPassword, flags.PrivKey)
		if err != nil {
			logger.Fatal("😥 Failed to load private key: ", zap.Error(err))
		}
		srv, err := operator.New(privateKey, logger, []byte(cmd.Version), flags.OperatorID, flags.OutputPath, flags.EthEndpointURL)
		if err != nil {
			logger.Fatal("😥 Failed to create new operator instance: ", zap.Error(err))
		}
		logger.Info("🚀 Starting DKG operator", zap.Uint64("at port", flags.Port))
		if err := srv.Start(uint16(flags.Port), flags.ServerTLSCertPath, flags.ServerTLSKeyPath); err != nil {
			log.Fatalf("Error in operator %v", err)
		}
		return nil
	},
}
