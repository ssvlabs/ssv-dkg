package operator

import (
	"context"
	"fmt"
	"log"
	"time"

	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/operator"
)

func init() {
	flags.OperatorPrivateKeyFlag(StartDKGOperator)
	flags.OperatorPrivateKeyPassFlag(StartDKGOperator)
	flags.OperatorPortFlag(StartDKGOperator)
	flags.StoreShareFlag(StartDKGOperator)
	flags.ConfigPathFlag(StartDKGOperator)
	flags.LogLevelFlag(StartDKGOperator)
	flags.LogFormatFlag(StartDKGOperator)
	flags.LogLevelFormatFlag(StartDKGOperator)
	flags.ResultPathFlag(StartDKGOperator)
	flags.LogFilePathFlag(StartDKGOperator)
	flags.DBPathFlag(StartDKGOperator)
	flags.DBReportingFlag(StartDKGOperator)
	flags.DBGCIntervalFlag(StartDKGOperator)
	if err := viper.BindPFlag("operatorPrivKey", StartDKGOperator.PersistentFlags().Lookup("operatorPrivKey")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorPrivKeyPassword", StartDKGOperator.PersistentFlags().Lookup("operatorPrivKeyPassword")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("port", StartDKGOperator.PersistentFlags().Lookup("port")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("storeShare", StartDKGOperator.PersistentFlags().Lookup("storeShare")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("outputPath", StartDKGOperator.PersistentFlags().Lookup("outputPath")); err != nil {
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
	if err := viper.BindPFlag("DBPath", StartDKGOperator.PersistentFlags().Lookup("DBPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("DBReporting", StartDKGOperator.PersistentFlags().Lookup("DBReporting")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("DBGCInterval", StartDKGOperator.PersistentFlags().Lookup("DBGCInterval")); err != nil {
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
		err := cli_utils.SetViperConfig(cmd)
		if err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-operator")
		if err != nil {
			return err
		}
		// workaround for https://github.com/spf13/viper/issues/233
		if err := viper.BindPFlag("outputPath", cmd.Flags().Lookup("outputPath")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		if err := viper.BindPFlag("storeShare", cmd.Flags().Lookup("storeShare")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		dkg.OutputPath = viper.GetString("outputPath")
		dkg.StoreShare = viper.GetBool("storeShare")
		operatorPrivKey := viper.GetString("operatorPrivKey")
		if operatorPrivKey == "" {
			logger.Fatal("😥 Failed to get operator private key flag value: ", zap.Error(err))
		}
		operatorPrivKeyPassword := viper.GetString("operatorPrivKeyPassword")
		privateKey, err := cli_utils.OpenPrivateKey(operatorPrivKey, operatorPrivKeyPassword)
		if err != nil {
			logger.Fatal(err.Error())
		}
		// Database
		var DBOptions basedb.Options
		DBPath := viper.GetString("DBPath")
		DBReporting := viper.GetBool("DBReporting")
		DBGCInterval := viper.GetString("DBGCInterval")
		DBOptions.Path = DBPath
		DBOptions.Reporting = DBReporting
		DBOptions.GCInterval, err = time.ParseDuration(DBGCInterval)
		if err != nil {
			logger.Fatal("😥 Failed to parse DBGCInterval: ", zap.Error(err))
		}
		DBOptions.Ctx = context.Background()
		if err != nil {
			logger.Fatal("😥 Failed to open DB: ", zap.Error(err))
		}
		srv := operator.New(privateKey, logger, DBOptions)
		port := viper.GetUint64("port")
		if port == 0 {
			logger.Fatal("😥 Failed to get operator info file path flag value: ", zap.Error(err))
		}
		pubKey, err := crypto.EncodePublicKey(&privateKey.PublicKey)
		if err != nil {
			logger.Fatal(err.Error())
			return err
		}
		logger.Info("🚀 Starting DKG operator", zap.Uint64("port", port), zap.String("public key", string(pubKey)))
		if err := srv.Start(uint16(port)); err != nil {
			log.Fatalf("Error in operator %v", err)
			return err
		}
		return nil
	},
}
