package initiator

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"

	"github.com/ethereum/go-ethereum/common"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
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
	flags.ForkVersionFlag(StartReshare)
	flags.AddDepositResultStorePathFlag(StartReshare)
	flags.AddKeysharesOutputPathFlag(StartReshare)
	flags.ConfigPathFlag(StartReshare)
	flags.LogLevelFlag(StartReshare)
	flags.LogFormatFlag(StartReshare)
	flags.LogLevelFormatFlag(StartReshare)
	flags.LogFilePathFlag(StartReshare)
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
	if err := viper.BindPFlag("operatorsInfoPath", StartReshare.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("owner", StartReshare.PersistentFlags().Lookup("owner")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("nonce", StartReshare.PersistentFlags().Lookup("nonce")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("ssvPayloadResultsPath", StartReshare.PersistentFlags().Lookup("ssvPayloadResultsPath")); err != nil {
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
		logger := zap.L().Named("dkg-initiator")
		// Check paths for results
		ssvPayloadResultsPath := viper.GetString("ssvPayloadResultsPath")
		if ssvPayloadResultsPath == "" {
			logger.Fatal("😥 Failed to get ssv payload path flag value: ", zap.Error(err))
		}
		_, err = os.Stat(ssvPayloadResultsPath)
		if os.IsNotExist(err) {
			logger.Fatal("😥 Folder to store SSV payload file does not exist: ", zap.Error(err))
		}
		// Load operators TODO: add more sources.
		operatorFile := viper.GetString("operatorsInfoPath")
		if operatorFile == "" {
			logger.Fatal("😥 Failed to get operator info file path flag value: ", zap.Error(err))
		}

		opsfile, err := os.ReadFile(operatorFile)
		if err != nil {
			logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
		}

		opMap, err := initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
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
		var oldID [24]byte
		oldIDFlagValue, err := hex.DecodeString(viper.GetString("oldID"))
		copy(oldID[:], oldIDFlagValue)
		privKeyPath := viper.GetString("initiatorPrivKey")
		if privKeyPath == "" {
			logger.Fatal("😥 Failed to get initiator key flag value", zap.Error(err))
		}
		var privateKey *rsa.PrivateKey
		pass := viper.GetString("initiatorPrivKeyPassword")
		if pass != "" {
			// check if a password string a valid path, then read password from the file
			if _, err := os.Stat(pass); err != nil {
				logger.Fatal("😥 Password file: ", zap.Error(err))
			}
			keyStorePassword, err := os.ReadFile(pass)
			if err != nil {
				logger.Fatal("😥 Error reading password file: ", zap.Error(err))
			}
			encryptedJSON, err := os.ReadFile(privKeyPath)
			if err != nil {
				logger.Fatal("😥 Cant read operator`s key file", zap.Error(err))
			}
			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedJSON, string(keyStorePassword))
			if err != nil {
				logger.Fatal(err.Error())
			}
		} else {
			privateKey, err = crypto.PrivateKey(privKeyPath)
			if err != nil {
				logger.Fatal(err.Error())
			}
		}

		dkgInitiator := initiator.New(privateKey, opMap, logger)
		owner := viper.GetString("owner")
		if owner == "" {
			logger.Fatal("😥 Failed to get owner address flag value: ", zap.Error(err))
		}
		nonce := viper.GetUint64("nonce")
		id := crypto.NewID()
		keyShares, err := dkgInitiator.StartReshare(id, oldID, oldParts, newParts, common.HexToAddress(owner), nonce)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		payloadFinalPath := fmt.Sprintf("%s/payload_%s_%s.json", ssvPayloadResultsPath, keyShares.Payload.PublicKey, hex.EncodeToString(id[:]))
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", payloadFinalPath))
		err = utils.WriteJSON(payloadFinalPath, keyShares)
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
