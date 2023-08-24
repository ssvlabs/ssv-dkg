package operator

import (
	"fmt"
	"log"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	flags.OperatorPrivateKeyFlag(StartDKGServer)
	flags.OperatorPortFlag(StartDKGServer)
	viper.BindPFlag("privKey", StartDKGServer.PersistentFlags().Lookup("privKey"))
	viper.BindPFlag("port", StartDKGServer.PersistentFlags().Lookup("port"))
}

var StartDKGServer = &cobra.Command{
	Use:   "start-dkg-server",
	Short: "Starts an instance of DKG",
	Run: func(cmd *cobra.Command, args []string) {
		fmt.Println(`
		██████╗ ██╗  ██╗ ██████╗      ██████╗ ██████╗ ███████╗██████╗  █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██╔═══██╗██╔══██╗██╔════╝██╔══██╗██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║   ██║██████╔╝█████╗  ██████╔╝███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║   ██║██╔═══╝ ██╔══╝  ██╔══██╗██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ╚██████╔╝██║     ███████╗██║  ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝      ╚═════╝ ╚═╝     ╚══════╝╚═╝  ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := logging.SetGlobalLogger("debug", "capital", "console"); err != nil {
			log.Fatal(err)
		}
		logger := zap.L().Named(cmd.Short)

		viper.SetConfigName("operator")
		viper.SetConfigType("yaml")
		viper.AddConfigPath("./config")
		err := viper.ReadInConfig()
		if err != nil {
			logger.Fatal("fatal error config file")
		}
		privKeyPath := viper.GetString("privKey")
		if privKeyPath == "" {
			logger.Fatal("failed to get operator private key flag value", zap.Error(err))
		}
		// Load and decode the private key
		// TODO: consider adding secure keystore and provide password instead of plain text priv key
		privateKey, err := load.PrivateKey(privKeyPath)
		if err != nil {
			log.Fatalf("Failed to load private key: %v", err)
		}

		srv := server.New(privateKey)

		port := viper.GetUint64("port")
		if port == 0 {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		logger.Info("Starting DKG instance at", zap.Uint64("port", port))
		if err := srv.Start(uint16(port)); err != nil {
			log.Fatalf("Error in server %v", err)
		}
	},
}
