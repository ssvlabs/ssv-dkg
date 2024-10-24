package initiator

import (
	"fmt"
	"strings"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/cli/flags"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
)

func init() {
	flags.SetHealthCheckFlags(HealthCheck)
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

		for i, s := range ips {
			ips[i] = strings.TrimRight(s, "/")
		}

		dkgInitiator, err := initiator.New(nil, logger, cmd.Version, nil, true)
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
