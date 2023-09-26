package operator

import (
	"crypto/rsa"
	"fmt"
	"log"
	"os"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/operator"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	flags.OperatorPrivateKeyFlag(StartDKGOperator)
	flags.OperatorPrivateKeyPassFlag(StartDKGOperator)
	flags.OperatorPortFlag(StartDKGOperator)
	flags.AddStoreShareFlag(StartDKGOperator)
	flags.ConfigPathFlag(StartDKGOperator)
	flags.LogLevelFlag(StartDKGOperator)
	flags.LogFormatFlag(StartDKGOperator)
	flags.LogLevelFormatFlag(StartDKGOperator)
	flags.LogFilePathFlag(StartDKGOperator)
	if err := viper.BindPFlag("privKey", StartDKGOperator.PersistentFlags().Lookup("privKey")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("password", StartDKGOperator.PersistentFlags().Lookup("password")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("port", StartDKGOperator.PersistentFlags().Lookup("port")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("storeShare", StartDKGOperator.PersistentFlags().Lookup("storeShare")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logLevel", StartDKGOperator.PersistentFlags().Lookup("logLevel")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logFormat", StartDKGOperator.PersistentFlags().Lookup("logFormat")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logLevelFormat", StartDKGOperator.PersistentFlags().Lookup("logLevelFormat")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logFilePath", StartDKGOperator.PersistentFlags().Lookup("logFilePath")); err != nil {
		panic(err)
	}
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
		viper.SetConfigType("yaml")
		configPath, err := flags.GetConfigPathFlagValue(cmd)
		if err != nil {
			return err
		}
		if configPath != "" {
			viper.SetConfigFile(configPath)
		} else {
			viper.AddConfigPath("./config")
		}
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
		logLevel := viper.GetString("logLevel")
		logFormat := viper.GetString("logFormat")
		logLevelFormat := viper.GetString("logLevelFormat")
		logFilePath := viper.GetString("logFilePath")
		// If the log file doesn't exist, create it
		_, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if err := logging.SetGlobalLogger(logLevel, logFormat, logLevelFormat, &logging.LogFileOptions{FileName: logFilePath}); err != nil {
			return fmt.Errorf("logging.SetGlobalLogger: %w", err)
		}
		logger := zap.L().Named("dkg-operator")
		if err != nil {
			logger.Warn("couldn't find config file, its ok if you are using cli params")
		}
		privKeyPath := viper.GetString("privKey")
		if privKeyPath == "" {
			logger.Fatal("failed to get operator private key flag value", zap.Error(err))
		}
		var privateKey *rsa.PrivateKey
		pass := viper.GetString("password")
		if pass != "" {
			// check if a password string a valid path, then read password from the file
			if _, err := os.Stat(pass); err != nil {
				logger.Fatal("Cant read password file", zap.Error(err))
			}
			keyStorePassword, err := os.ReadFile(pass)
			if err != nil {
				logger.Fatal("Error reading Password file", zap.Error(err))
				return err
			}
			encryptedJSON, err := os.ReadFile(privKeyPath)
			if err != nil {
				logger.Fatal("cant read operator`s key file", zap.Error(err))
				return err
			}
			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedJSON, string(keyStorePassword))
			if err != nil {
				logger.Fatal("cant read operator`s key file", zap.Error(err))
				return err
			}
		} else {
			logger.Fatal("please provide password string or path to password file", zap.Error(err))
			return err
		}
		srv := operator.New(privateKey, logger)
		port := viper.GetUint64("port")
		if port == 0 {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
			return err
		}
		pubKey, err := crypto.EncodePublicKey(&privateKey.PublicKey)
		if err != nil {
			logger.Fatal(err.Error())
			return err
		}
		logger.Info("starting DKG operator", zap.Uint64("port", port), zap.String("public key", string(pubKey)))
		if err := srv.Start(uint16(port)); err != nil {
			log.Fatalf("Error in operator %v", err)
			return err
		}
		return nil
	},
}
