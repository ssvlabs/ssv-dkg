package operator

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/bloxapp/ssv-dkg-tool/cli/flags"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
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
	flags.AddStoreShareFlag(StartDKGServer)
	viper.BindPFlag("privKey", StartDKGServer.PersistentFlags().Lookup("privKey"))
	viper.BindPFlag("password", StartDKGServer.PersistentFlags().Lookup("password"))
	viper.BindPFlag("port", StartDKGServer.PersistentFlags().Lookup("port"))
	viper.BindPFlag("storeShare", StartDKGServer.PersistentFlags().Lookup("storeShare"))
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
		logger := zap.L().Named("dkg-server")

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
		var privateKey *rsa.PrivateKey
		pass := viper.GetString("password")
		if pass != "" {
			encryptedJSON, err := os.ReadFile(privKeyPath)
			if err != nil {
				logger.Fatal(err.Error())
			}

			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedJSON, pass)
			if err != nil {
				logger.Fatal(err.Error())
			}
		} else {
			privateKey, err = load.PrivateKey(privKeyPath)
			if err != nil {
				logger.Fatal(err.Error())
			}
		}

		srv := server.New(privateKey)

		port := viper.GetUint64("port")
		if port == 0 {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}
		pubKey, err := crypto.EncodePublicKey(&privateKey.PublicKey)
		if err != nil {
			logger.Fatal(err.Error())
		}
		logger.Info("starting DKG server", zap.Uint64("port", port), zap.String("public key", string(pubKey)))
		if err := srv.Start(uint16(port)); err != nil {
			log.Fatalf("Error in server %v", err)
		}
	},
}
