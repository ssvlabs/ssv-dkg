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
	flags.OperatorsInfoFileFlag(StartDKG)
	flags.OperatorsInfoPathFlag(StartDKG)
	flags.OperatorIDsFlag(StartDKG)
	flags.OwnerAddressFlag(StartDKG)
	flags.NonceFlag(StartDKG)
	flags.ForkVersionFlag(StartDKG)
	flags.AddDepositResultStorePathFlag(StartDKG)
	flags.AddKeysharesOutputPathFlag(StartDKG)
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
	if err := viper.BindPFlag("operatorsInfoFile", StartDKG.PersistentFlags().Lookup("operatorsInfoFile")); err != nil {
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
	if err := viper.BindPFlag("fork", StartDKG.PersistentFlags().Lookup("fork")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("depositOutputPath", StartDKG.PersistentFlags().Lookup("depositOutputPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("keysharesOutputPath", StartDKG.PersistentFlags().Lookup("keysharesOutputPath")); err != nil {
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
		if _, err := os.Stat(logFilePath); os.IsNotExist(err) {
			_, err := os.Create(logFilePath)
			if err != nil {
				return err
			}
		}
		if err := logging.SetGlobalLogger(logLevel, logFormat, logLevelFormat, &logging.LogFileOptions{FileName: logFilePath}); err != nil {
			return fmt.Errorf("logging.SetGlobalLogger: %w", err)
		}
		logger := zap.L().Named("dkg-initiator")
		// Check paths for results
		depositOutputPath := viper.GetString("depositOutputPath")
		if depositOutputPath == "" {
			logger.Fatal("😥 Failed to get deposit result path flag value: ", zap.Error(err))
		}
		if stat, err := os.Stat(depositOutputPath); os.IsNotExist(err) {
			logger.Fatal("😥 Folder to store deposit file does not exist: ", zap.Error(err))
		} else {
			if !stat.IsDir() {
				logger.Fatal("😥 Provided depositOutputPath flag is not a directory: ", zap.Error(err))
			}
		}
		// Check paths for results
		keysharesOutputPath := viper.GetString("keysharesOutputPath")
		if keysharesOutputPath == "" {
			logger.Fatal("😥 Failed to get ssv payload path flag value: ", zap.Error(err))
		}
		if stat, err := os.Stat(keysharesOutputPath); os.IsNotExist(err) {
			logger.Fatal("😥 Folder to store SSV payload file does not exist: ", zap.Error(err))
		} else {
			if !stat.IsDir() {
				logger.Fatal("😥 Provided keysharesOutputPath flag is not a directory: ", zap.Error(err))
			}
		}
		// Load operators TODO: add more sources.
		operatorsInfoFile := viper.GetString("operatorsInfoFile")
		operatorsInfoPath := viper.GetString("operatorsInfoPath")
		if operatorsInfoFile == "" && operatorsInfoPath == "" {
			logger.Fatal("😥 Operator info file path or dir path have not provided")
		}
		if operatorsInfoFile != "" && operatorsInfoPath != "" {
			logger.Fatal("😥 Please provide either operator info file path or directory path to look for 'operators_info.json' file, not both")
		}
		var opMap initiator.Operators
		if operatorsInfoFile != "" {
			logger.Info("📖 reading operators info JSON file")
			if stat, err := os.Stat(operatorsInfoFile); err == nil && !stat.IsDir() {
				opsfile, err := os.ReadFile(operatorsInfoFile)
				if err != nil {
					logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
				}
				opMap, err = initiator.LoadOperatorsJson(opsfile)
				if err != nil {
					logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
				}
			} else {
				logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
			}
		}
		if operatorsInfoPath != "" {
			logger.Info("📖 looking operators info 'operators_info.json' file", zap.String("at path", operatorsInfoPath))
			if stat, err := os.Stat(operatorsInfoPath); err == nil && stat.IsDir() {
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
		pass := viper.GetString("initiatorPrivKeyPassword")
		if privKeyPath != "" && !generateInitiatorKey {
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
		}
		if privKeyPath == "" && generateInitiatorKey {
			logger.Info("🔑 generating new initiator RSA key pair + password")
			pk, priv, err := rsaencryption.GenerateKeys()
			if err != nil {
				logger.Fatal("Failed to generate operator keys", zap.Error(err))
			}
			password, err = crypto.GenerateSecurePassword()
			if err != nil {
				logger.Fatal("Failed to generate operator keys", zap.Error(err))
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
		fork := viper.GetString("fork")
		if fork == "" {
			logger.Fatal("😥 Failed to get fork version flag value: ", zap.Error(err))
		}
		var forkHEX [4]byte
		switch fork {
		case "prater":
			forkHEX = [4]byte{0x00, 0x00, 0x10, 0x20}
		case "mainnet":
			forkHEX = [4]byte{0, 0, 0, 0}
		case "now_test_network":
			forkHEX = [4]byte{0x99, 0x99, 0x99, 0x99}
		default:
			logger.Fatal("😥 Please provide a valid fork name: mainnet, prater, or now_test_network")
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
		depositData, keyShares, err := dkgInitiator.StartDKG(id, withdrawAddress.Bytes(), parts, forkHEX, fork, ownerAddress, nonce)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		// Save deposit file
		logger.Info("🎯  All data is validated.")
		depositFinalPath := fmt.Sprintf("%s/deposit_%s.json", depositOutputPath, depositData.PubKey)
		logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
		err = utils.WriteJSON(depositFinalPath, []initiator.DepositDataJson{*depositData})
		if err != nil {
			logger.Warn("Failed writing deposit data file: ", zap.Error(err))
		}
		keysharesFinalPath := fmt.Sprintf("%s/keyshares-%v.json", keysharesOutputPath, depositData.PubKey)
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
		err = utils.WriteJSON(keysharesFinalPath, keyShares)
		if err != nil {
			logger.Warn("Failed writing keyshares file: ", zap.Error(err))
		}
		if privKeyPath == "" && generateInitiatorKey {
			rsaKeyPath := fmt.Sprintf("%s/encrypted_private_key-%v.json", keysharesOutputPath, depositData.PubKey)
			err = os.WriteFile(rsaKeyPath, encryptedRSAJSON, 0644)
			if err != nil {
				logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
			}
			rsaKeyPasswordPath := fmt.Sprintf("%s/password-%v.txt", keysharesOutputPath, depositData.PubKey)
			err = os.WriteFile(rsaKeyPasswordPath, []byte(password), 0644)
			if err != nil {
				logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
			}
			logger.Info("Private key encrypted and stored at", zap.String("path", keysharesOutputPath))
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
