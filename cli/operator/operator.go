package operator

import (
	"context"
	"fmt"
	"log"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/operator"
)

// shutdownTimeout bounds how long Stop will wait for in-flight HTTP handlers
// to drain on SIGTERM/SIGINT before we force the process down.
const shutdownTimeout = 30 * time.Second

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

		sigs := make(chan os.Signal, 1)
		signal.Notify(sigs, syscall.SIGINT, syscall.SIGTERM)
		defer signal.Stop(sigs)
		go func() {
			sig := <-sigs
			logger.Info("shutdown signal received, stopping operator", zap.String("signal", sig.String()))
			ctx, cancel := context.WithTimeout(context.Background(), shutdownTimeout)
			defer cancel()
			if err := srv.Stop(ctx); err != nil {
				logger.Error("operator shutdown error", zap.Error(err))
			}
		}()

		logger.Info("🚀 Starting DKG operator", zap.Uint64("at port", flags.Port))
		if err := srv.Start(uint16(flags.Port), flags.ServerTLSCertPath, flags.ServerTLSKeyPath); err != nil {
			log.Fatalf("Error in operator %v", err)
		}
		return nil
	},
}
