package initiator

import (
	"fmt"
	"strings"

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
		logger, err := zap.NewDevelopment()
		if err != nil {
			return fmt.Errorf("create logger: %w", err)
		}
		logger = logger.Named("dkg-initiator")
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		ips, err := cmd.Flags().GetStringSlice("ip")
		if err != nil {
			return fmt.Errorf("😥 %w", err)
		}

		for i, s := range ips {
			ips[i] = strings.TrimRight(s, "/")
		}

		dkgInitiator, err := initiator.New(nil, logger, cmd.Version, nil, true)
		if err != nil {
			return fmt.Errorf("😥 %w", err)
		}
		err = dkgInitiator.Ping(ips)
		if err != nil {
			return fmt.Errorf("😥 Error: %w", err)
		}
		return nil
	},
}
