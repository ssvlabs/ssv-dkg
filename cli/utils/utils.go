package utils

import (
	"context"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

// global base flags
var (
	PrivKey         string
	PrivKeyPassword string
	OutputPath      string
	LogLevel        string
	LogFormat       string
	LogLevelFormat  string
	LogFilePath     string
)

// init flags
var (
	OperatorsInfo        string
	OperatorsInfoPath    string
	OperatorIDs          []string
	GenerateInitiatorKey bool
	WithdrawAddress      common.Address
	Network              string
	OwnerAddress         common.Address
	Nonce                uint64
	Validators           uint64
)

// reshare flags
var (
	NewOperatorIDs []string
	CeremonyID     [24]byte
)

// operator flags
var (
	Port         uint64
	StoreShare   bool
	DBPath       string
	DBReporting  bool
	DBGCInterval string
)

// SetViperConfig reads a yaml config file if provided
func SetViperConfig(cmd *cobra.Command) error {
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
		fmt.Println("⚠️ config file was not provided, using flag parameters")
	}
	return nil
}

// SetGlobalLogger creates a logger
func SetGlobalLogger(cmd *cobra.Command, name string) (*zap.Logger, error) {
	// If the log file doesn't exist, create it
	_, err := os.OpenFile(LogFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o644)
	if err != nil {
		return nil, err
	}
	if err := logging.SetGlobalLogger(LogLevel, LogFormat, LogLevelFormat, &logging.LogFileOptions{FileName: LogFilePath}); err != nil {
		return nil, fmt.Errorf("logging.SetGlobalLogger: %w", err)
	}
	logger := zap.L().Named(name)
	return logger, nil
}

// OpenPrivateKey reads an RSA key from file.
// If passwordFilePath is provided, treats privKeyPath as encrypted
// If passwordFilePath is not provided, treats privKeyPath as plaintext
func OpenPrivateKey(passwordFilePath, privKeyPath string) (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey
	var err error
	if passwordFilePath != "" {
		fmt.Println("🔑 path to password file is provided - decrypting")
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("😥 Password file doesn`t exist: %s", err)
		}
		encryptedRSAJSON, err := os.ReadFile(privKeyPath)
		if err != nil {
			return nil, fmt.Errorf("😥 Cant read operator`s key file: %s", err)
		}
		keyStorePassword, err := os.ReadFile(passwordFilePath)
		if err != nil {
			return nil, fmt.Errorf("😥 Error reading password file: %s", err)
		}
		privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, string(keyStorePassword))
		if err != nil {
			return nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
		}
	} else {
		fmt.Println("🔑 password for key NOT provided - trying to read plaintext key")
		privateKey, err = crypto.PrivateKey(privKeyPath)
		if err != nil {
			return nil, fmt.Errorf("😥 Error reading plaintext private key from file: %s", err)
		}
	}
	return privateKey, nil
}

// GenerateRSAKeyPair generates a RSA key pair. Password either supplied as path or generated at random.
func GenerateRSAKeyPair(passwordFilePath, privKeyPath string) (*rsa.PrivateKey, []byte, error) {
	var privateKey *rsa.PrivateKey
	var err error
	var password string
	_, priv, err := rsaencryption.GenerateKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Failed to generate operator keys: %s", err)
	}
	if passwordFilePath != "" {
		fmt.Println("🔑 path to password file is provided")
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("😥 Password file doesn`t exist: %s", err)
		}
		keyStorePassword, err := os.ReadFile(passwordFilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("😥 Error reading password file: %s", err)
		}
		password = string(keyStorePassword)
	} else {
		password, err = crypto.GenerateSecurePassword()
		if err != nil {
			return nil, nil, fmt.Errorf("😥 Failed to generate operator keys: %s", err)
		}
	}
	encryptedData, err := keystorev4.New().Encrypt(priv, password)
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Failed to encrypt private key: %s", err)
	}
	encryptedRSAJSON, err := json.Marshal(encryptedData)
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Failed to marshal encrypted data to JSON: %s", err)
	}
	privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, password)
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
	}
	return privateKey, encryptedRSAJSON, nil
}

// ReadOperatorsInfoFile reads operators data from path
func ReadOperatorsInfoFile(operatorsInfoPath string) (initiator.Operators, error) {
	var opMap initiator.Operators
	fmt.Printf("📖 looking operators info 'operators_info.json' file: %s \n", operatorsInfoPath)
	stat, err := os.Stat(operatorsInfoPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
	}
	if stat.IsDir() {
		filePath := operatorsInfoPath + "operators_info.json"
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("😥 Failed to find operator info file at provided path: %s", err)
		}
		opsfile, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
		}
		opMap, err = initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to load operators: %s", err)
		}
	} else {
		fmt.Println("📖 reading operators info JSON file")
		opsfile, err := os.ReadFile(operatorsInfoPath)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
		}
		opMap, err = initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to load operators: %s", err)
		}
	}
	return opMap, nil
}

func SetBaseFlags(cmd *cobra.Command) {
	flags.ConfigPathFlag(cmd)
	flags.PrivateKeyFlag(cmd)
	flags.PrivateKeyPassFlag(cmd)
	flags.ResultPathFlag(cmd)
	flags.LogLevelFlag(cmd)
	flags.LogFormatFlag(cmd)
	flags.LogLevelFormatFlag(cmd)
	flags.LogFilePathFlag(cmd)

}

func SetInitFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.OperatorsInfoFlag(cmd)
	flags.OperatorsInfoPathFlag(cmd)
	flags.OperatorIDsFlag(cmd)
	flags.OwnerAddressFlag(cmd)
	flags.NonceFlag(cmd)
	flags.NetworkFlag(cmd)
	flags.GenerateInitiatorKeyFlag(cmd)
	flags.WithdrawAddressFlag(cmd)
	flags.ValidatorsFlag(cmd)
}

func SetReshareFlags(cmd *cobra.Command) {
	SetInitFlags(cmd)
	flags.OldIDFlag(cmd)
	flags.NewOperatorIDsFlag(cmd)
}

func SetOperatorFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.OperatorPortFlag(cmd)
	flags.StoreShareFlag(cmd)
	flags.DBPathFlag(cmd)
	flags.DBReportingFlag(cmd)
	flags.DBGCIntervalFlag(cmd)
}

// BindFlags binds flags to yaml config parameters
func BindBaseFlags(cmd *cobra.Command) error {
	if err := viper.BindPFlag("privKey", cmd.PersistentFlags().Lookup("privKey")); err != nil {
		return err
	}
	if err := viper.BindPFlag("privKeyPassword", cmd.PersistentFlags().Lookup("privKeyPassword")); err != nil {
		return err
	}
	if err := viper.BindPFlag("outputPath", cmd.PersistentFlags().Lookup("outputPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logLevel", cmd.PersistentFlags().Lookup("logLevel")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logFormat", cmd.PersistentFlags().Lookup("logFormat")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logLevelFormat", cmd.PersistentFlags().Lookup("logLevelFormat")); err != nil {
		return err
	}
	if err := viper.BindPFlag("logFilePath", cmd.PersistentFlags().Lookup("logFilePath")); err != nil {
		return err
	}
	PrivKey = viper.GetString("privKey")
	PrivKeyPassword = viper.GetString("privKeyPassword")
	OutputPath = viper.GetString("outputPath")
	if stat, err := os.Stat(OutputPath); err != nil || !stat.IsDir() {
		return fmt.Errorf("😥 Error to to open path to store results %s", err.Error())
	}
	LogLevel = viper.GetString("logLevel")
	LogFormat = viper.GetString("logFormat")
	LogLevelFormat = viper.GetString("logLevelFormat")
	LogFilePath = viper.GetString("logFilePath")
	if LogFilePath == "" {
		fmt.Println("⚠️ debug log path was not provided, using default: ./initiator_debug.log")
	}
	return nil
}

// BindInitiatorBaseFlags binds flags to yaml config parameters
func BindInitiatorBaseFlags(cmd *cobra.Command) error {
	var err error
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("generateInitiatorKey", cmd.PersistentFlags().Lookup("generateInitiatorKey")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorIDs", cmd.PersistentFlags().Lookup("operatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfo", cmd.PersistentFlags().Lookup("operatorsInfo")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfoPath", cmd.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("owner", cmd.PersistentFlags().Lookup("owner")); err != nil {
		return err
	}
	if err := viper.BindPFlag("nonce", cmd.PersistentFlags().Lookup("nonce")); err != nil {
		return err
	}
	OperatorIDs = viper.GetStringSlice("operatorIDs")
	if len(OperatorIDs) == 0 {
		return fmt.Errorf("😥 Operator IDs flag cant be empty")
	}
	OperatorsInfo = viper.GetString("operatorsInfo")
	OperatorsInfoPath = viper.GetString("operatorsInfoPath")
	if OperatorsInfo == "" && OperatorsInfoPath == "" {
		return fmt.Errorf("😥 Operators string or path have not provided")
	}
	if OperatorsInfo != "" && OperatorsInfoPath != "" {
		return fmt.Errorf("😥 Please provide either operator info string or path, not both")
	}
	GenerateInitiatorKey = viper.GetBool("generateInitiatorKey")
	if PrivKey == "" && !GenerateInitiatorKey {
		return fmt.Errorf("😥 Initiator key flag should be provided")
	}
	if PrivKey != "" && GenerateInitiatorKey {
		return fmt.Errorf("😥 Please provide either private key path or generate command, not both")
	}
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 Failed to get owner address flag value")
	}
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 Failed to parse owner address: %s", err)
	}
	Nonce = viper.GetUint64("nonce")
	return nil
}

// BindInitFlags binds flags to yaml config parameters for the initial DKG
func BindInitFlags(cmd *cobra.Command) error {
	if err := BindInitiatorBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("withdrawAddress", cmd.PersistentFlags().Lookup("withdrawAddress")); err != nil {
		return err
	}
	if err := viper.BindPFlag("network", cmd.Flags().Lookup("network")); err != nil {
		return err
	}
	if err := viper.BindPFlag("validators", cmd.Flags().Lookup("validators")); err != nil {
		return err
	}
	withdrawAddr := viper.GetString("withdrawAddress")
	if withdrawAddr == "" {
		return fmt.Errorf("😥 Failed to get withdrawal address flag value")
	}
	var err error
	WithdrawAddress, err = utils.HexToAddress(withdrawAddr)
	if err != nil {
		return fmt.Errorf("😥 Failed to parse withdraw address: %s", err.Error())
	}
	Network = viper.GetString("network")
	if Network == "" {
		return fmt.Errorf("😥 Failed to get fork version flag value")
	}
	Validators = viper.GetUint64("validators")
	if Validators > 100 || Validators == 0 {
		return fmt.Errorf("🚨 Amount of generated validators should be less 0<x<100")
	}
	return nil
}

// BindReshareFlags binds flags to yaml config parameters for the resharing ceremony of DKG
func BindReshareFlags(cmd *cobra.Command) error {
	if err := BindInitiatorBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("newOperatorIDs", cmd.PersistentFlags().Lookup("newOperatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("oldID", cmd.PersistentFlags().Lookup("oldID")); err != nil {
		return err
	}
	NewOperatorIDs = viper.GetStringSlice("newOperatorIDs")
	if len(NewOperatorIDs) == 0 {
		return fmt.Errorf("😥 New operator IDs flag cant be empty")
	}
	var err error
	id := viper.GetString("oldID")
	oldIDFlagValue, err := hex.DecodeString(id)
	if err != nil {
		return err
	}
	copy(CeremonyID[:], oldIDFlagValue)
	return nil
}

// BindOperatorFlags binds flags to yaml config parameters for the resharing ceremony of DKG
func BindOperatorFlags(cmd *cobra.Command) error {
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("port", cmd.PersistentFlags().Lookup("port")); err != nil {
		return err
	}
	if err := viper.BindPFlag("storeShare", cmd.PersistentFlags().Lookup("storeShare")); err != nil {
		return err
	}
	if err := viper.BindPFlag("DBPath", cmd.PersistentFlags().Lookup("DBPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("DBReporting", cmd.PersistentFlags().Lookup("DBReporting")); err != nil {
		return err
	}
	if err := viper.BindPFlag("DBGCInterval", cmd.PersistentFlags().Lookup("DBGCInterval")); err != nil {
		return err
	}
	Port = viper.GetUint64("port")
	if Port <= 0 {
		return fmt.Errorf("😥 Wrong port provided")
	}
	StoreShare = viper.GetBool("storeShare")
	DBPath = viper.GetString("DBPath")
	DBReporting = viper.GetBool("DBReporting")
	DBGCInterval = viper.GetString("DBGCInterval")
	return nil
}

// StingSliceToUintArray converts the string slice to uint64 slice
func StingSliceToUintArray(flagdata []string) ([]uint64, error) {
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

// LoadOperators loads operators data from raw json or file path
func LoadOperators() (initiator.Operators, error) {
	opmap := make(map[uint64]initiator.Operator)
	var err error
	if OperatorsInfo != "" {
		opmap, err = initiator.LoadOperatorsJson([]byte(OperatorsInfo))
		if err != nil {
			return nil, err
		}
	}
	if OperatorsInfoPath != "" {
		opmap, err = ReadOperatorsInfoFile(OperatorsInfoPath)
		if err != nil {
			return nil, err
		}
	}
	return opmap, nil
}

// LoadRSAPrivKey loads RSA private key from path or generates a new key pair
func LoadRSAPrivKey() (*rsa.PrivateKey, []byte, error) {
	var privateKey *rsa.PrivateKey
	var encryptedRSAJSON []byte
	var err error
	if PrivKey != "" && !GenerateInitiatorKey {
		privateKey, err = OpenPrivateKey(PrivKeyPassword, PrivKey)
		if err != nil {
			return nil, nil, err
		}
	}
	if PrivKey == "" && GenerateInitiatorKey {
		privateKey, encryptedRSAJSON, err = GenerateRSAKeyPair(PrivKeyPassword, PrivKey)
		if err != nil {
			return nil, nil, err
		}
	}
	return privateKey, encryptedRSAJSON, nil
}

// GetOperatorDB creates a new Badger DB instance at provided path
func GetOperatorDB() (basedb.Options, error) {
	var DBOptions basedb.Options
	var err error
	DBOptions.Path = DBPath
	DBOptions.Reporting = DBReporting
	DBOptions.GCInterval, err = time.ParseDuration(DBGCInterval)
	if err != nil {
		return basedb.Options{}, fmt.Errorf("😥 Failed to parse DBGCInterval: %s", err)
	}
	DBOptions.Ctx = context.Background()
	if err != nil {
		return basedb.Options{}, fmt.Errorf("😥 Failed to open DB: %s", err)
	}
	return DBOptions, nil
}

func WriteInitResults(depositDataArr []*initiator.DepositDataJson, keySharesArr []*initiator.KeyShares, nonces []uint64, ids [][24]byte, encryptedRSAJSON []byte, logger *zap.Logger) {
	if len(depositDataArr) != int(Validators) || len(keySharesArr) != int(Validators) {
		logger.Fatal("")
	}
	timestamp := time.Now().Format(time.RFC3339)
	dir := fmt.Sprintf("%s/ceremony-%s", OutputPath, timestamp)
	err := os.Mkdir(dir, os.ModePerm)
	if err != nil {
		logger.Fatal("Failed to create a ceremony directory: ", zap.Error(err))
	}
	if Validators > 1 {
		for i := 0; i < int(Validators); i++ {
			nestedDir := fmt.Sprintf("%s/%s", dir, depositDataArr[i].PubKey)
			err := os.Mkdir(nestedDir, os.ModePerm)
			if err != nil {
				logger.Fatal("Failed to create a ceremony directory: ", zap.Error(err))
			}
			depositFinalPath := fmt.Sprintf("%s/deposit_data-%s.json", nestedDir, depositDataArr[i].PubKey)
			logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
			err = utils.WriteJSON(depositFinalPath, depositDataArr[i])
			if err != nil {
				logger.Fatal("Failed writing deposit data file: ", zap.Error(err))
			}
			// Save results
			keysharesFinalPath := fmt.Sprintf("%s/keyshares-%s-%s-%d-%v.json", nestedDir, keySharesArr[i].Payload.PublicKey, OwnerAddress.String(), nonces[i], hex.EncodeToString(ids[i][:]))\
			logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
			err = utils.WriteJSON(keysharesFinalPath, keySharesArr[i])
			if err != nil {
				logger.Warn("Failed writing keyshares file: ", zap.Error(err))
			}
		}
		// Write all to one JSON file
		depositFinalPath := fmt.Sprintf("%s/deposit_data.json", dir)
		logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
		err := utils.WriteJSON(depositFinalPath, depositDataArr)
		if err != nil {
			logger.Fatal("Failed writing deposit data file: ", zap.Error(err))
		}
		// Save results
		keysharesFinalPath := fmt.Sprintf("%s/keyshares.json", dir)
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
		err = utils.WriteJSON(keysharesFinalPath, keySharesArr)
		if err != nil {
			logger.Warn("Failed writing keyshares file: ", zap.Error(err))
		}
	} else if Validators == 1 {
		depositFinalPath := fmt.Sprintf("%s/deposit_data-%s.json", dir, depositDataArr[0].PubKey)
		logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
		err = utils.WriteJSON(depositFinalPath, depositDataArr[0])
		if err != nil {
			logger.Fatal("Failed writing deposit data file: ", zap.Error(err))
		}
		// Save results
		keysharesFinalPath := fmt.Sprintf("%s/keyshares-%s-%s-%d-%v.json", dir, keySharesArr[0].Payload.PublicKey, OwnerAddress.String(), Nonce, hex.EncodeToString(ids[0][:]))
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
		err = utils.WriteJSON(keysharesFinalPath, keySharesArr[0])
		if err != nil {
			logger.Warn("Failed writing keyshares file: ", zap.Error(err))
		}
	}
	if encryptedRSAJSON != nil {
		rsaKeyPath := fmt.Sprintf("%s/ceremony_encrypted_key.json", dir)
		err := os.WriteFile(rsaKeyPath, encryptedRSAJSON, 0o644)
		if err != nil {
			logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
		}
		if PrivKeyPassword == "" {
			rsaKeyPasswordPath := fmt.Sprintf("%s/ceremony_password.json", dir)
			password, err := crypto.GenerateSecurePassword()
			if err != nil {
				logger.Fatal("Failed to generate secure password", zap.Error(err))
			}
			err = os.WriteFile(rsaKeyPasswordPath, []byte(password), 0o644)
			if err != nil {
				logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
			}
		}
		logger.Info("Private key encrypted and stored at", zap.String("path", rsaKeyPath))
		logger.Info("Password stored at", zap.String("path", rsaKeyPasswordPath))
	}
}
