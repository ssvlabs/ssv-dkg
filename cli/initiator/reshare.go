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
		// workaround for https://github.com/spf13/viper/issues/233
		viper.BindPFlag("logFilePath", cmd.Flags().Lookup("logFilePath"))
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
		// workaround for https://github.com/spf13/viper/issues/233
		viper.BindPFlag("outputPath", cmd.Flags().Lookup("outputPath"))
		outputPath := viper.GetString("outputPath")
		if outputPath == "" {
			logger.Fatal("😥 Failed to get deposit result path flag value: ", zap.Error(err))
		}
		if stat, err := os.Stat(outputPath); err != nil || !stat.IsDir() {
			logger.Fatal("😥 Error to to open path to store results", zap.Error(err))
		}
		// Load operators TODO: add more sources.
		operatorsInfo := viper.GetString("operatorsInfo")
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
			logger.Info("📖 looking operators info 'operators_info.json' file", zap.String("at path", operatorsInfoPath))
			stat, err := os.Stat(operatorsInfoPath)
			if os.IsNotExist(err) {
				logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
			}
			if stat.IsDir() {
				filePath := operatorsInfoPath + "operators_info.json"
				if _, err := os.Stat(filePath); os.IsNotExist(err) {
					logger.Fatal("😥 Failed to find operator info file at provided path: ", zap.Error(err))
				}
				opsfile, err := os.ReadFile(filePath)
				if err != nil {
					logger.Fatal("😥 Failed to read operator info file:", zap.Error(err))
				}
				opMap, err = initiator.LoadOperatorsJson(opsfile)
				if err != nil {
					logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
				}
			} else {
				logger.Info("📖 reading operators info JSON file")
				opsfile, err := os.ReadFile(operatorsInfoPath)
				if err != nil {
					logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
				}
				opMap, err = initiator.LoadOperatorsJson(opsfile)
				if err != nil {
					logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
				}
			}
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
		logger.Info("🔑 opening initiator RSA private key file")
		if pass != "" {
			logger.Info("🔑 password for key provided - decrypting")
			// check if a password string a valid path, then read password from the file
			if _, err := os.Stat(pass); os.IsNotExist(err) {
				logger.Fatal("😥 Password file doesn`t exist: ", zap.Error(err))
			}
			encryptedRSAJSON, err := os.ReadFile(privKeyPath)
			if err != nil {
				logger.Fatal("😥 Cant read operator`s key file", zap.Error(err))
			}
			keyStorePassword, err := os.ReadFile(pass)
			if err != nil {
				logger.Fatal("😥 Error reading password file: ", zap.Error(err))
			}
			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, string(keyStorePassword))
			if err != nil {
				logger.Fatal(err.Error())
			}
		} else {
			logger.Info("🔑 password for key NOT provided - trying to read plaintext key")
			privateKey, err = crypto.PrivateKey(privKeyPath)
			if err != nil {
				logger.Fatal("😥 Error reading plaintext private key from file: ", zap.Error(err))
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
