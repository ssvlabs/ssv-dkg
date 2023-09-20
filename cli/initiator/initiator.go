package initiator

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"os"
	"strconv"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/load"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"

	"github.com/ethereum/go-ethereum/common"

	"github.com/bloxapp/ssv/logging"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

func init() {
	flags.InitiatorPrivateKeyFlag(StartDKG)
	flags.InitiatorPrivateKeyPassFlag(StartDKG)
	flags.WithdrawAddressFlag(StartDKG)
	flags.OperatorsInfoFlag(StartDKG)
	flags.OperatorIDsFlag(StartDKG)
	flags.OwnerAddressFlag(StartDKG)
	flags.NonceFlag(StartDKG)
	flags.ForkVersionFlag(StartDKG)
	flags.AddDepositResultStorePathFlag(StartDKG)
	flags.AddSSVPayloadResultStorePathFlag(StartDKG)
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
	if err := viper.BindPFlag("depositResultsPath", StartDKG.PersistentFlags().Lookup("depositResultsPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("ssvPayloadResultsPath", StartDKG.PersistentFlags().Lookup("ssvPayloadResultsPath")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("initiatorPrivKey", StartDKG.PersistentFlags().Lookup("initiatorPrivKey")); err != nil {
		panic(err)
	}
	if err := viper.BindPFlag("initiatorPrivKeyPassword", StartDKG.PersistentFlags().Lookup("initiatorPrivKeyPassword")); err != nil {
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
		_, err = os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
		if err != nil {
			return err
		}
		if err := logging.SetGlobalLogger(logLevel, logFormat, logLevelFormat, logFilePath); err != nil {
			return fmt.Errorf("logging.SetGlobalLogger: %w", err)
		}
		logger := zap.L().Named("dkg-initiator")
		// Check paths for results
		depositResultsPath := viper.GetString("depositResultsPath")
		if depositResultsPath == "" {
			logger.Fatal("failed to get deposit result path flag value", zap.Error(err))
		}
		_, err = os.Stat(depositResultsPath)
		if os.IsNotExist(err) {
			logger.Fatal("Folder to store deposit file does not exist", zap.Error(err))
		}
		// Check paths for results
		ssvPayloadResultsPath := viper.GetString("ssvPayloadResultsPath")
		if ssvPayloadResultsPath == "" {
			logger.Fatal("failed to get ssv payload path flag value", zap.Error(err))
		}
		_, err = os.Stat(ssvPayloadResultsPath)
		if os.IsNotExist(err) {
			logger.Fatal("Folder to store SSV payload file does not exist", zap.Error(err))
		}
		// Load operators TODO: add more sources.
		operatorFile := viper.GetString("operatorsInfoPath")
		if operatorFile == "" {
			logger.Fatal("failed to get operator info file path flag value", zap.Error(err))
		}

		opsfile, err := os.ReadFile(operatorFile)
		if err != nil {
			logger.Fatal("failed to read operator info file", zap.Error(err))
		}

		opMap, err := load.LoadOperatorsJson(opsfile)
		if err != nil {
			logger.Fatal("Failed to load operators: ", zap.Error(err))
		}
		participants := viper.GetStringSlice("operatorIDs")
		if participants == nil {
			logger.Fatal("failed to get operator IDs flag value", zap.Error(err))
		}
		parts, err := loadParticipants(participants)
		if err != nil {
			logger.Fatal("failed: ", zap.Error(err))
		}
		privKeyPath := viper.GetString("initiatorPrivKey")
		if privKeyPath == "" {
			logger.Fatal("failed to get initiator key flag value", zap.Error(err))
		}
		var privateKey *rsa.PrivateKey
		pass := viper.GetString("initiatorPrivKeyPassword")
		if pass != "" {
			// check if a password string a valid path, then read password from the file
			if _, err := os.Stat(pass); err != nil {
				logger.Fatal("Cant read password file", zap.Error(err))
			}
			keyStorePassword, err := os.ReadFile(pass)
			if err != nil {
				logger.Fatal("Error reading Password file", zap.Error(err))
			}
			encryptedJSON, err := os.ReadFile(privKeyPath)
			if err != nil {
				logger.Fatal("cant read operator`s key file", zap.Error(err))
			}
			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedJSON, string(keyStorePassword))
			if err != nil {
				logger.Fatal(err.Error())
			}
		} else {
			privateKey, err = load.PrivateKey(privKeyPath)
			if err != nil {
				logger.Fatal(err.Error())
			}
		}

		dkgInitiator := initiator.New(privateKey, opMap, logger)
		withdrawAddr := viper.GetString("withdrawAddress")
		if withdrawAddr == "" {
			logger.Fatal("failed to get withdrawal address flag value", zap.Error(err))
		}
		fork := viper.GetString("fork")
		if fork == "" {
			logger.Fatal("failed to get fork version flag value", zap.Error(err))
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
			logger.Fatal("please provide a valid fork name: mainnet, prater, or now_test_network")
		}
		owner := viper.GetString("owner")
		if owner == "" {
			logger.Fatal("failed to get owner address flag value", zap.Error(err))
		}
		nonce := viper.GetUint64("nonce")
		withdrawPubKey, err := hex.DecodeString(withdrawAddr)
		if err != nil {
			logger.Fatal("failed to decode withdrawal public key", zap.Error(err))
		}
		depositData, keyShares, err := dkgInitiator.StartDKG(withdrawPubKey, parts, forkHEX, fork, common.HexToAddress(owner), nonce)
		if err != nil {
			logger.Fatal("failed to initiate DKG ceremony", zap.Error(err))
		}
		// Save deposit file
		logger.Info("DKG finished. All data is validated. Writing deposit data json to file %s\n", zap.String("path", depositResultsPath))
		err = utils.WriteJSON(depositResultsPath+"deposit_"+fmt.Sprint(depositData.PubKey)+".json", []initiator.DepositDataJson{*depositData})
		if err != nil {
			logger.Warn("Failed writing deposit data file", zap.Error(err))
		}

		logger.Info("DKG finished. All data is validated. Writing keyshares to file: %s\n", zap.String("path", ssvPayloadResultsPath))
		err = utils.WriteJSON(ssvPayloadResultsPath+"payload_"+fmt.Sprint(depositData.PubKey)+".json", keyShares)
		if err != nil {
			logger.Warn("Failed writing keyshares file", zap.Error(err))
		}

		logger.Info("DKG protocol finished successfull")
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
			return nil, fmt.Errorf("cant load operator err: %v , data: %v, ", err, flagdata[i])
		}
		partsarr = append(partsarr, opid)
	}
	return partsarr, nil
}
