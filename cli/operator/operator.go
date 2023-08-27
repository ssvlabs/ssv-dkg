package operator

import (
	"fmt"
	"log"
	"os"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	flags.OperatorPrivateKeyFlag(StartDKGServer)
	flags.OperatorPrivateKeyPassFlag(StartDKGServer)
	flags.OperatorPortFlag(StartDKGServer)
	viper.BindPFlag("privKey", StartDKGServer.PersistentFlags().Lookup("privKey"))
	viper.BindPFlag("port", StartDKGServer.PersistentFlags().Lookup("port"))
	viper.BindPFlag("port", StartDKGServer.PersistentFlags().Lookup("port"))
	viper.BindPFlag("password", StartDKGServer.PersistentFlags().Lookup("password"))
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
		pass := viper.GetString("password")
		if pass == "" {
			logger.Fatal("failed to get operator password flag value", zap.Error(err))
		}
		encryptedJSON, err := os.ReadFile(privKeyPath)
		if err != nil {
			logger.Fatal(err.Error())
		}

		privateKey, err := crypto.ConvertEncryptedPemToPrivateKey(encryptedJSON, pass)
		if err != nil {
			logger.Fatal(err.Error())
		}

		srv := server.New(privateKey)

		port := viper.GetUint64("port")
		if port == 0 {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		pubKey, err := crypto.EncodePublicKey(&privateKey.PublicKey)
		privString := crypto.ExtractPrivateKey(privateKey)
		logger.Info("Starting DKG instance at ", zap.Uint64("port", port), zap.String("public key", string(pubKey)), zap.String("priv key", privString))
		if err := srv.Start(uint16(port)); err != nil {
			log.Fatalf("Error in server %v", err)
		}
	},
}
