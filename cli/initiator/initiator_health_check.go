package initiator

import (
	"fmt"
	"strings"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
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

		operatorsInfo, err := cmd.Flags().GetString("operatorsInfo")
		if err != nil {
			return fmt.Errorf("😥 %w", err)
		}
		operatorsInfoPath, err := cmd.Flags().GetString("operatorsInfoPath")
		if err != nil {
			return fmt.Errorf("😥 %w", err)
		}
		if operatorsInfo != "" && operatorsInfoPath != "" {
			return fmt.Errorf("😥 operators info can be provided either as a raw JSON string, or path to a file, not both")
		}
		if operatorsInfo == "" && operatorsInfoPath == "" {
			return fmt.Errorf("😥 operators info should be provided either as a raw JSON string, or path to a file")
		}

		opMap, err := cli_utils.LoadOperators(logger, operatorsInfo, operatorsInfoPath)
		if err != nil {
			return fmt.Errorf("😥 %w", err)
		}

		if len(ips) == 0 {
			ips = make([]string, 0, len(opMap))
			for _, op := range opMap {
				ips = append(ips, op.Addr)
			}
		} else {
			for _, ip := range ips {
				if opMap.ByAddr(ip) == nil {
					return fmt.Errorf("😥 operator address %s not found in operators list", ip)
				}
			}
		}

		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, nil, true)
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
