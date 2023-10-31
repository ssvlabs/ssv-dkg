package initiator

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
)

func init() {
	flags.InitiatorPrivateKeyFlag(StartReshare)
	flags.InitiatorPrivateKeyPassFlag(StartReshare)
	flags.WithdrawAddressFlag(StartReshare)
	flags.OperatorsInfoFlag(StartReshare)
	flags.OperatorIDsFlag(StartReshare)
	flags.OldIDFlag(StartReshare)
	flags.NewOperatorIDsFlag(StartReshare)
	flags.OwnerAddressFlag(StartReshare)
	flags.NonceFlag(StartReshare)
	flags.ConfigPathFlag(StartReshare)
	flags.LogLevelFlag(StartReshare)
	flags.LogFormatFlag(StartReshare)
	flags.LogLevelFormatFlag(StartReshare)
	flags.LogFilePathFlag(StartReshare)
	flags.ResultPathFlag(StartReshare)
	if err := viper.BindPFlag("withdrawAddress", StartReshare.PersistentFlags().Lookup("withdrawAddress")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorIDs", StartReshare.PersistentFlags().Lookup("operatorIDs")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("newOperatorIDs", StartReshare.PersistentFlags().Lookup("newOperatorIDs")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("oldID", StartReshare.PersistentFlags().Lookup("oldID")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorsInfo", StartDKG.PersistentFlags().Lookup("operatorsInfo")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorsInfoPath", StartDKG.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("owner", StartReshare.PersistentFlags().Lookup("owner")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("nonce", StartReshare.PersistentFlags().Lookup("nonce")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("outputPath", StartDKG.PersistentFlags().Lookup("outputPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("initiatorPrivKey", StartReshare.PersistentFlags().Lookup("initiatorPrivKey")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("initiatorPrivKeyPassword", StartReshare.PersistentFlags().Lookup("initiatorPrivKeyPassword")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logLevel", StartReshare.PersistentFlags().Lookup("logLevel")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logFormat", StartReshare.PersistentFlags().Lookup("logFormat")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logLevelFormat", StartReshare.PersistentFlags().Lookup("logLevelFormat")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logFilePath", StartReshare.PersistentFlags().Lookup("logFilePath")); err != nil {
		panic(err)
	}
}

var StartReshare = &cobra.Command{
	Use:   "reshare",
	Short: "Reshare an existing key to new operators",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		▓█████▄  ██ ▄█▀  ▄████     ██▀███  ▓█████   ██████  ██░ ██  ▄▄▄       ██▀███  ▓█████ 
		▒██▀ ██▌ ██▄█▒  ██▒ ▀█▒   ▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▓█   ▀ 
		░██   █▌▓███▄░ ▒██░▄▄▄░   ▓██ ░▄█ ▒▒███   ░ ▓██▄   ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
		░▓█▄   ▌▓██ █▄ ░▓█  ██▓   ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
		░▒████▓ ▒██▒ █▄░▒▓███▀▒   ░██▓ ▒██▒░▒████▒▒██████▒▒░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▒
		▒▒▓  ▒ ▒ ▒▒ ▓▒ ░▒   ▒    ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
		░ ▒  ▒ ░ ░▒ ▒░  ░   ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
		░ ░  ░ ░ ░░ ░ ░ ░   ░      ░░   ░    ░   ░  ░  ░   ░  ░░ ░  ░   ▒     ░░   ░    ░   
		░    ░  ░         ░       ░        ░  ░      ░   ░  ░  ░      ░  ░   ░        ░  ░
		░`)
		err := cli_utils.SetViperConfig(cmd)
		if err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator")
		if err != nil {
			return err
		}
		// workaround for https://github.com/spf13/viper/issues/233
		if err := viper.BindPFlag("outputPath", cmd.Flags().Lookup("outputPath")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		outputPath := viper.GetString("outputPath")
		if outputPath == "" {
			logger.Fatal("😥 Failed to get deposit result path flag value: ", zap.Error(err))
		}
		if stat, err := os.Stat(outputPath); err != nil || !stat.IsDir() {
			logger.Fatal("😥 Error to to open path to store results", zap.Error(err))
		}
		// Load operators TODO: add more sources.
		if err := viper.BindPFlag("operatorsInfo", cmd.Flags().Lookup("operatorsInfo")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		operatorsInfo := viper.GetString("operatorsInfo")
		if err := viper.BindPFlag("operatorsInfoPath", cmd.Flags().Lookup("operatorsInfoPath")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		operatorsInfoPath := viper.GetString("operatorsInfoPath")
		if operatorsInfo == "" && operatorsInfoPath == "" {
			logger.Fatal("😥 Operators string or path have not provided")
		}
		if operatorsInfo != "" && operatorsInfoPath != "" {
			logger.Fatal("😥 Please provide either operator info string or path, not both")
		}
		var opMap initiator.Operators
		if operatorsInfo != "" {
			logger.Info("📖 reading raw JSON string of operators info")
			opMap, err = initiator.LoadOperatorsJson([]byte(operatorsInfo))
			if err != nil {
				logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
			}
		}
		if operatorsInfoPath != "" {
			opMap, err = cli_utils.ReadOperatorsInfoFile(operatorsInfoPath)
			if err != nil {
				logger.Fatal(err.Error())
			}
		}
		if err := viper.BindPFlag("operatorIDs", cmd.Flags().Lookup("operatorIDs")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		oldParticipants := viper.GetStringSlice("operatorIDs")
		if oldParticipants == nil {
			logger.Fatal("😥 Failed to get operator IDs flag value: ", zap.Error(err))
		}
		oldParts, err := loadParticipants(oldParticipants)
		if err != nil {
			logger.Fatal("😥 Failed to load old participants: ", zap.Error(err))
		}
		newParticipants := viper.GetStringSlice("newOperatorIDs")
		newParts, err := loadParticipants(newParticipants)
		if err != nil {
			logger.Fatal("😥 Failed to load new participants: ", zap.Error(err))
		}
		// Read old ID
		var oldID [24]byte
		oldIDFlagValue, err := hex.DecodeString(viper.GetString("oldID"))
		copy(oldID[:], oldIDFlagValue)
		// Open initiator's private RSA key
		if err := viper.BindPFlag("initiatorPrivKey", cmd.Flags().Lookup("initiatorPrivKey")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		initiatorPrivKey := viper.GetString("initiatorPrivKey")
		if initiatorPrivKey == "" {
			logger.Fatal("😥 Failed to get initiator key flag value", zap.Error(err))
		}
		var privateKey *rsa.PrivateKey
		if err := viper.BindPFlag("initiatorPrivKeyPassword", cmd.Flags().Lookup("initiatorPrivKeyPassword")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		initiatorPrivKeyPassword := viper.GetString("initiatorPrivKeyPassword")
		logger.Info("🔑 opening initiator RSA private key file")
		privateKey, err = cli_utils.OpenPrivateKey(initiatorPrivKeyPassword, initiatorPrivKey)
		if err != nil {
			logger.Fatal(err.Error())
		}
		// create initiator instance
		dkgInitiator := initiator.New(privateKey, opMap, logger)
		if err := viper.BindPFlag("owner", cmd.Flags().Lookup("owner")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		owner := viper.GetString("owner")
		if owner == "" {
			logger.Fatal("😥 Failed to get owner address flag value: ", zap.Error(err))
		}
		if err := viper.BindPFlag("nonce", cmd.Flags().Lookup("nonce")); err != nil {
			logger.Fatal("😥 Failed to bind a flag: ", zap.Error(err))
		}
		nonce := viper.GetUint64("nonce")
		// create a new ID for resharing
		id := crypto.NewID()
		// Start the ceremony
		keyShares, err := dkgInitiator.StartReshare(id, oldID, oldParts, newParts, common.HexToAddress(owner), nonce)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		// Save results
		keysharesFinalPath := fmt.Sprintf("%s/keyshares-reshared-%v-%v.json", outputPath, keyShares.Payload.PublicKey, hex.EncodeToString(id[:]))
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
		err = utils.WriteJSON(keysharesFinalPath, keyShares)
		if err != nil {
			logger.Warn("Failed writing keyshares file: ", zap.Error(err))
		}

		fmt.Println(`
		▓█████▄  ██▓  ██████  ▄████▄   ██▓    ▄▄▄       ██▓ ███▄ ▄███▓▓█████  ██▀███  
		▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▓██▒   ▒████▄    ▓██▒▓██▒▀█▀ ██▒▓█   ▀ ▓██ ▒ ██▒
		░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░   ▒██  ▀█▄  ▒██▒▓██    ▓██░▒███   ▓██ ░▄█ ▒
		░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██░   ░██▄▄▄▄██ ░██░▒██    ▒██ ▒▓█  ▄ ▒██▀▀█▄  
		░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░██████▒▓█   ▓██▒░██░▒██▒   ░██▒░▒████▒░██▓ ▒██▒
		 ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▓  ░▒▒   ▓▒█░░▓  ░ ▒░   ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
		 ░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒   ░ ░ ▒  ░ ▒   ▒▒ ░ ▒ ░░  ░      ░ ░ ░  ░  ░▒ ░ ▒░
		 ░ ░  ░  ▒ ░░  ░  ░  ░          ░ ░    ░   ▒    ▒ ░░      ░      ░     ░░   ░ 
		   ░     ░        ░  ░ ░          ░  ░     ░  ░ ░         ░      ░  ░   ░     
		 ░                   ░                                                        
		 
		 This tool was not audited.
		 When using distributed key generation you understand all the risks involved with
		 experimental cryptography.  
		 `)
		return nil
	},
}
