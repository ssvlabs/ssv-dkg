package initiator

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"strconv"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	"go.uber.org/zap"
)

func init() {
	flags.InitiatorPrivateKeyFlag(StartDKG)
	flags.InitiatorPrivateKeyPassFlag(StartDKG)
	flags.GenerateInitiatorKeyFlag(StartDKG)
	flags.WithdrawAddressFlag(StartDKG)
	flags.OperatorsInfoFlag(StartDKG)
	flags.OperatorsInfoPathFlag(StartDKG)
	flags.OperatorIDsFlag(StartDKG)
	flags.OwnerAddressFlag(StartDKG)
	flags.NonceFlag(StartDKG)
	flags.NetworkFlag(StartDKG)
	flags.ResultPathFlag(StartDKG)
	flags.ConfigPathFlag(StartDKG)
	flags.LogLevelFlag(StartDKG)
	flags.LogFormatFlag(StartDKG)
	flags.LogLevelFormatFlag(StartDKG)
	flags.LogFilePathFlag(StartDKG)
	if err := viper.BindPFlag("withdrawAddress", StartDKG.PersistentFlags().Lookup("withdrawAddress")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorIDs", StartDKG.PersistentFlags().Lookup("operatorIDs")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorsInfo", StartDKG.PersistentFlags().Lookup("operatorsInfo")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("operatorsInfoPath", StartDKG.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("owner", StartDKG.PersistentFlags().Lookup("owner")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("nonce", StartDKG.PersistentFlags().Lookup("nonce")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("network", StartDKG.PersistentFlags().Lookup("network")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("outputPath", StartDKG.PersistentFlags().Lookup("outputPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("initiatorPrivKey", StartDKG.PersistentFlags().Lookup("initiatorPrivKey")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("initiatorPrivKeyPassword", StartDKG.PersistentFlags().Lookup("initiatorPrivKeyPassword")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("generateInitiatorKey", StartDKG.PersistentFlags().Lookup("generateInitiatorKey")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logLevel", StartDKG.PersistentFlags().Lookup("logLevel")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logFormat", StartDKG.PersistentFlags().Lookup("logFormat")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logLevelFormat", StartDKG.PersistentFlags().Lookup("logLevelFormat")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("logFilePath", StartDKG.PersistentFlags().Lookup("logFilePath")); err != nil {
		panic(err)
	}
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
		viper.SetConfigType("yaml")
		configPath, err := flags.GetConfigPathFlagValue(cmd)
		if err != nil {
			return err
		}
		if configPath != "" {
			viper.SetConfigFile(configPath)
		}
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return err
			}
			fmt.Print("⚠️ config file was not provided, using flag parameters \n")
		}
		logLevel := viper.GetString("logLevel")
		logFormat := viper.GetString("logFormat")
		logLevelFormat := viper.GetString("logLevelFormat")
		// workaround for https://github.com/spf13/viper/issues/233
		viper.BindPFlag("logFilePath", cmd.Flags().Lookup("logFilePath"))
		logFilePath := viper.GetString("logFilePath")
		if logFilePath == "" {
			fmt.Print("⚠️ debug log path was not provided, using default: ./initiator_debug.log \n")
		}
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
		participants := viper.GetStringSlice("operatorIDs")
		if participants == nil {
			logger.Fatal("😥 Failed to get operator IDs flag value: ", zap.Error(err))
		}
		parts, err := loadParticipants(participants)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		privKeyPath := viper.GetString("initiatorPrivKey")
		generateInitiatorKey := viper.GetBool("generateInitiatorKey")
		if privKeyPath == "" && !generateInitiatorKey {
			logger.Fatal("😥 Initiator key flag should be provided")
		}
		if privKeyPath != "" && generateInitiatorKey {
			logger.Fatal("😥 Please provide either private key path or generate command, not both")
		}
		var privateKey *rsa.PrivateKey
		var encryptedRSAJSON []byte
		var password string
		passwordFilePath := viper.GetString("initiatorPrivKeyPassword")
		if privKeyPath != "" && !generateInitiatorKey {
			logger.Info("🔑 opening initiator RSA private key file")
			if passwordFilePath != "" {
				logger.Info("🔑 path to password file is provided - decrypting")
				// check if a password string a valid path, then read password from the file
				if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
					logger.Fatal("😥 Password file doesn`t exist: ", zap.Error(err))
				}
				encryptedRSAJSON, err := os.ReadFile(privKeyPath)
				if err != nil {
					logger.Fatal("😥 Cant read operator`s key file", zap.Error(err))
				}
				keyStorePassword, err := os.ReadFile(passwordFilePath)
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
		}
		if privKeyPath == "" && generateInitiatorKey {
			logger.Info("🔑 generating new initiator RSA key pair + password")
			pk, priv, err := rsaencryption.GenerateKeys()
			if err != nil {
				logger.Fatal("Failed to generate operator keys", zap.Error(err))
			}
			if passwordFilePath != "" {
				logger.Info("🔑 path to password file is provided")
				// check if a password string a valid path, then read password from the file
				if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
					logger.Fatal("😥 Password file doesn`t exist: ", zap.Error(err))
				}
				keyStorePassword, err := os.ReadFile(passwordFilePath)
				if err != nil {
					logger.Fatal("😥 Error reading password file: ", zap.Error(err))
				}
				password = string(keyStorePassword)
			} else {
				password, err = crypto.GenerateSecurePassword()
				if err != nil {
					logger.Fatal("Failed to generate operator keys", zap.Error(err))
				}
			}
			logger.Info("Generated public key (base64)", zap.String("pk", base64.StdEncoding.EncodeToString(pk)))
			encryptedData, err := keystorev4.New().Encrypt(priv, password)
			if err != nil {
				logger.Fatal("Failed to encrypt private key", zap.Error(err))
			}
			encryptedRSAJSON, err = json.Marshal(encryptedData)
			if err != nil {
				logger.Fatal("Failed to marshal encrypted data to JSON", zap.Error(err))
			}
			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, password)
			if err != nil {
				logger.Fatal(err.Error())
			}
		}

		dkgInitiator := initiator.New(privateKey, opMap, logger)
		withdrawAddr := viper.GetString("withdrawAddress")
		if withdrawAddr == "" {
			logger.Fatal("😥 Failed to get withdrawal address flag value: ", zap.Error(err))
		}
		network := viper.GetString("network")
		if network == "" {
			logger.Fatal("😥 Failed to get fork version flag value: ", zap.Error(err))
		}
		var forkHEX [4]byte
		switch network {
		case "prater":
			forkHEX = [4]byte{0x00, 0x00, 0x10, 0x20}
		case "pyrmont":
			forkHEX = [4]byte{0x00, 0x00, 0x20, 0x09}
		case "mainnet":
			forkHEX = [4]byte{0, 0, 0, 0}
		default:
			logger.Fatal("😥 Please provide a valid network name: mainnet/prater/pyrmont")
		}
		owner := viper.GetString("owner")
		if owner == "" {
			logger.Fatal("😥 Failed to get owner address flag value: ", zap.Error(err))
		}
		ownerAddress, err := utils.HexToAddress(owner)
		if err != nil {
			logger.Fatal("😥 Failed to parse owner address: ", zap.Error(err))
		}
		nonce := viper.GetUint64("nonce")
		withdrawAddress, err := utils.HexToAddress(withdrawAddr)
		if err != nil {
			logger.Fatal("😥 Failed to parse withdraw address: ", zap.Error(err))
		}
		id := crypto.NewID()
		depositData, keyShares, err := dkgInitiator.StartDKG(id, withdrawAddress.Bytes(), parts, forkHEX, network, ownerAddress, nonce)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		// Save deposit file
		logger.Info("🎯  All data is validated.")
		depositFinalPath := fmt.Sprintf("%s/deposit_%s.json", outputPath, depositData.PubKey)
		logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
		err = utils.WriteJSON(depositFinalPath, []initiator.DepositDataJson{*depositData})
		if err != nil {
			logger.Warn("Failed writing deposit data file: ", zap.Error(err))
		}
		keysharesFinalPath := fmt.Sprintf("%s/keyshares-%v.json", outputPath, depositData.PubKey)
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
		err = utils.WriteJSON(keysharesFinalPath, keyShares)
		if err != nil {
			logger.Warn("Failed writing keyshares file: ", zap.Error(err))
		}
		if privKeyPath == "" && generateInitiatorKey {
			rsaKeyPath := fmt.Sprintf("%s/encrypted_private_key-%v.json", outputPath, depositData.PubKey)
			err = os.WriteFile(rsaKeyPath, encryptedRSAJSON, 0644)
			if err != nil {
				logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
			}
			if passwordFilePath == "" {
				rsaKeyPasswordPath := fmt.Sprintf("%s/password-%v.txt", outputPath, depositData.PubKey)
				err = os.WriteFile(rsaKeyPasswordPath, []byte(password), 0644)
				if err != nil {
					logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
				}
			}
			logger.Info("Private key encrypted and stored at", zap.String("path", outputPath))
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

func loadParticipants(flagdata []string) ([]uint64, error) {
	partsarr := make([]uint64, 0, len(flagdata))
	for i := 0; i < len(flagdata); i++ {
		opid, err := strconv.ParseUint(flagdata[i], 10, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("😥 cant load operator err: %v , data: %v, ", err, flagdata[i])
		}
		partsarr = append(partsarr, opid)
	}
	return partsarr, nil
}
