package initiator

import (
	"fmt"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv/logging"
)

func init() {
	cli_utils.SetHealthCheckFlags(HealthCheck)
}

var HealthCheck = &cobra.Command{
	Use:   "ping",
	Short: "Ping DKG operators",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		█████╗ ██╗  ██╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║██╔██╗ ██║██║   ██║   ██║███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := logging.SetGlobalLogger("debug", "json", "capitalColor", nil); err != nil {
			return fmt.Errorf("logging.SetGlobalLogger: %w", err)
		}
		logger := zap.L().Named("dkg-initiator")
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		ips, err := cmd.Flags().GetStringSlice("ip")
		if err != nil {
			logger.Fatal("😥", zap.Error(err))
		}
		dkgInitiator, err := initiator.New(nil, logger, cmd.Version, cli_utils.ClientCACertPath)
		if err != nil {
			logger.Fatal("😥", zap.Error(err))
		}
		err = dkgInitiator.Ping(ips)
		if err != nil {
			logger.Fatal("😥 Error: ", zap.Error(err))
		}
		return nil
	},
}
