package initiator

import (
	"context"
	"fmt"
	"log"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator/server"
)

func init() {
	flags.SetInitFlags(StartDKG)
	flags.SetInitServerFlags(StartServer)
}

var StartDKG = &cobra.Command{
	Use:   "init",
	Short: "Initiates a DKG protocol",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		█████╗ ██╗  ██╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║██╔██╗ ██║██║   ██║   ██║███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindInitFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator", flags.LogFilePath, flags.LogLevel, flags.LogFormat, flags.LogLevelFormat)
		if err != nil {
			return err
		}
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		// Load operators TODO: add more sources.
		operatorIDs, err := cli_utils.StringSliceToUintArray(flags.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load operator IDs: ", zap.Error(err))
		}
		opMap, err := cli_utils.LoadOperators(logger, flags.OperatorsInfo, flags.OperatorsInfoPath)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		ethNetwork := e2m_core.NetworkFromString(flags.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		// start the ceremony
		ctx := context.Background()
		initiator.StartInitCeremony(
			ctx,
			logger,
			opMap,
			operatorIDs,
			flags.OwnerAddress,
			flags.WithdrawAddress,
			flags.Nonce,
			flags.Amount,
			uint64(flags.Validators),
			ethNetwork,
			flags.ClientCACertPath,
			flags.TLSInsecure,
			flags.OutputPath,
			cmd.Version)
		return nil
	},
}

var StartServer = &cobra.Command{
	Use:   "initiator_server",
	Short: "Starts server to accept commands by http",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		█████╗ ██╗  ██╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║██╔██╗ ██║██║   ██║   ██║███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindInitServerFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator-server", flags.LogFilePath, flags.LogLevel, flags.LogFormat, flags.LogLevelFormat)
		if err != nil {
			return err
		}
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		srv, err := server.New(logger, cmd.Version, flags.OutputPath)
		if err != nil {
			logger.Fatal("😥 failed to create initiator server: ", zap.Error(err))
		}
		logger.Info("🚀 Starting DKG initiator server", zap.Uint64("at port", flags.Port))
		if err := srv.Start(uint16(flags.Port)); err != nil {
			logger.Fatal("error starting server", zap.Error(err))
		}
		return nil
	},
}
