package utils

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strconv"
	"strings"
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
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

// global base flags
var (
	ConfigPath     string
	OutputPath     string
	LogLevel       string
	LogFormat      string
	LogLevelFormat string
	LogFilePath    string
)

// init flags
var (
	OperatorsInfo                     string
	OperatorsInfoPath                 string
	OperatorIDs                       []string
	GenerateInitiatorKeyIfNotExisting bool
	WithdrawAddress                   common.Address
	Network                           string
	OwnerAddress                      common.Address
	Nonce                             uint64
	Validators                        uint64
)

// reshare flags
var (
	NewOperatorIDs       []string
	KeysharesFilePath    string
	CeremonySigsFilePath string
)

// operator flags
var (
	PrivKey         string
	PrivKeyPassword string
	Port            uint64
	OperatorID      uint64
	DBPath          string
	DBReporting     bool
	DBGCInterval    string
)

// SetViperConfig reads a yaml config file if provided
func SetViperConfig(cmd *cobra.Command) error {
	if err := viper.BindPFlag("configYAML", cmd.PersistentFlags().Lookup("configYAML")); err != nil {
		return err
	}
	configYAML := viper.GetString("configYAML")
	if configYAML != "" {
		if _, err := os.Stat(configYAML); os.IsNotExist(err) {
			return err
		}
		viper.SetConfigType("yaml")
		viper.SetConfigFile(configYAML)
		if err := viper.ReadInConfig(); err != nil {
			if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
				return err
			}
		}
		fmt.Printf("🗄️ config yaml file found at %s, using it \n", configYAML)
		return nil
	} else {
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
	flags.ConfigYAMLFlag(cmd)
	flags.ResultPathFlag(cmd)
	flags.LogLevelFlag(cmd)
	flags.LogFormatFlag(cmd)
	flags.LogLevelFormatFlag(cmd)
	flags.LogFilePathFlag(cmd)

}

func SetInitFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.ConfigPathFlag(cmd)
	flags.OperatorsInfoFlag(cmd)
	flags.OperatorsInfoPathFlag(cmd)
	flags.OperatorIDsFlag(cmd)
	flags.OwnerAddressFlag(cmd)
	flags.NonceFlag(cmd)
	flags.NetworkFlag(cmd)
	flags.GenerateInitiatorKeyIfNotExistingFlag(cmd)
	flags.WithdrawAddressFlag(cmd)
	flags.ValidatorsFlag(cmd)
}

func SetReshareFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.ConfigPathFlag(cmd)
	flags.OperatorsInfoFlag(cmd)
	flags.OperatorsInfoPathFlag(cmd)
	flags.NewOperatorIDsFlag(cmd)
	flags.KeysharesFilePathFlag(cmd)
	flags.CeremonySigsFilePathFlag(cmd)
}

func SetOperatorFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.PrivateKeyFlag(cmd)
	flags.PrivateKeyPassFlag(cmd)
	flags.OperatorPortFlag(cmd)
	flags.OperatorIDFlag(cmd)
	flags.DBPathFlag(cmd)
	flags.DBReportingFlag(cmd)
	flags.DBGCIntervalFlag(cmd)
}

func SetHealthCheckFlags(cmd *cobra.Command) {
	flags.AddPersistentStringSliceFlag(cmd, "ip", []string{}, "Operator ip:port", true)
}

// BindFlags binds flags to yaml config parameters
func BindBaseFlags(cmd *cobra.Command) error {
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
	if err := viper.BindPFlag("configPath", cmd.PersistentFlags().Lookup("configPath")); err != nil {
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
	ConfigPath = viper.GetString("configPath")
	if stat, err := os.Stat(ConfigPath); !stat.IsDir() || os.IsNotExist(err) {
		return fmt.Errorf("😥 configPath isnt a folder path or not exist: %s", err)
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
	if err := viper.BindPFlag("generateInitiatorKeyIfNotExisting", cmd.PersistentFlags().Lookup("generateInitiatorKeyIfNotExisting")); err != nil {
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
		return fmt.Errorf("🚨 Amount of generated validators should be 1 to 100")
	}
	GenerateInitiatorKeyIfNotExisting = viper.GetBool("generateInitiatorKeyIfNotExisting")
	return nil
}

// BindReshareFlags binds flags to yaml config parameters for the resharing ceremony of DKG
func BindReshareFlags(cmd *cobra.Command) error {
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("configPath", cmd.PersistentFlags().Lookup("configPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfo", cmd.PersistentFlags().Lookup("operatorsInfo")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfoPath", cmd.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("newOperatorIDs", cmd.PersistentFlags().Lookup("newOperatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("keysharesFilePath", cmd.PersistentFlags().Lookup("keysharesFilePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ceremonySigsFilePath", cmd.PersistentFlags().Lookup("ceremonySigsFilePath")); err != nil {
		return err
	}
	ConfigPath = viper.GetString("configPath")
	if stat, err := os.Stat(ConfigPath); !stat.IsDir() || os.IsNotExist(err) {
		return fmt.Errorf("😥 configPath isnt a folder path or not exist: %s", err)
	}
	OperatorsInfo = viper.GetString("operatorsInfo")
	OperatorsInfoPath = viper.GetString("operatorsInfoPath")
	if OperatorsInfo == "" && OperatorsInfoPath == "" {
		return fmt.Errorf("😥 Operators string or path have not provided")
	}
	if OperatorsInfo != "" && OperatorsInfoPath != "" {
		return fmt.Errorf("😥 Please provide either operator info string or path, not both")
	}
	NewOperatorIDs = viper.GetStringSlice("newOperatorIDs")
	if len(NewOperatorIDs) == 0 {
		return fmt.Errorf("😥 New operator IDs flag cant be empty")
	}
	if err := viper.BindPFlag("keysharesFilePath", cmd.PersistentFlags().Lookup("keysharesFilePath")); err != nil {
		return err
	}
	KeysharesFilePath = viper.GetString("keysharesFilePath")
	if KeysharesFilePath == "" {
		return fmt.Errorf("😥 please provide a path to keyshares json file")
	}
	if strings.Contains(KeysharesFilePath, "../") {
		return fmt.Errorf("😥 keysharesFilePath should not contain traversal")
	}
	if stat, err := os.Stat(KeysharesFilePath); stat.IsDir() || os.IsNotExist(err) {
		return fmt.Errorf("😥 keysharesFilePath is a folder path or not exist: %s", err)
	}
	CeremonySigsFilePath = viper.GetString("ceremonySigsFilePath")
	if CeremonySigsFilePath == "" {
		return fmt.Errorf("😥 please provide a path to ceremony signatures json file")
	}
	if strings.Contains(KeysharesFilePath, "../") {
		return fmt.Errorf("😥 ceremonySigsFilePath flag should not contain traversal")
	}
	if stat, err := os.Stat(KeysharesFilePath); stat.IsDir() || os.IsNotExist(err) {
		return fmt.Errorf("😥 ceremonySigsFilePath is a folder path or not exist: %s", err)
	}
	return nil
}

// BindOperatorFlags binds flags to yaml config parameters for the resharing ceremony of DKG
func BindOperatorFlags(cmd *cobra.Command) error {
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("privKey", cmd.PersistentFlags().Lookup("privKey")); err != nil {
		return err
	}
	if err := viper.BindPFlag("privKeyPassword", cmd.PersistentFlags().Lookup("privKeyPassword")); err != nil {
		return err
	}
	if err := viper.BindPFlag("port", cmd.PersistentFlags().Lookup("port")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorID", cmd.PersistentFlags().Lookup("operatorID")); err != nil {
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
	PrivKey = viper.GetString("privKey")
	PrivKeyPassword = viper.GetString("privKeyPassword")
	if PrivKey == "" {
		return fmt.Errorf("😥 Failed to get private key path flag value")
	}
	if PrivKeyPassword == "" {
		return fmt.Errorf("😥 Failed to get password for private key flag value")
	}
	Port = viper.GetUint64("port")
	if Port == 0 {
		return fmt.Errorf("😥 Wrong port provided")
	}
	OperatorID = viper.GetUint64("operatorID")
	if OperatorID == 0 {
		return fmt.Errorf("😥 Wrong operator ID provided")
	}
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

// LoadInitiatorRSAPrivKey loads RSA private key from path or generates a new key pair
func LoadInitiatorRSAPrivKey(generate bool) (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey
	privKeyPath := fmt.Sprintf("%s/initiator_encrypted_key.json", ConfigPath)
	privKeyPassPath := fmt.Sprintf("%s/initiator_password", ConfigPath)
	if generate {
		if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
			_, priv, err := rsaencryption.GenerateKeys()
			if err != nil {
				return nil, fmt.Errorf("😥 Failed to generate operator keys: %s", err)
			}
			if _, err := os.Stat(privKeyPassPath); os.IsNotExist(err) {
				password, err := crypto.GenerateSecurePassword()
				if err != nil {
					return nil, err
				}
				err = os.WriteFile(privKeyPassPath, []byte(password), 0o644)
				if err != nil {
					return nil, err
				}
			}
			keyStorePassword, err := os.ReadFile(privKeyPassPath)
			if err != nil {
				return nil, fmt.Errorf("😥 Error reading password file: %s", err)
			}
			encryptedRSAJSON, err := crypto.EncryptPrivateKey(priv, string(keyStorePassword))
			if err != nil {
				return nil, fmt.Errorf("😥 Failed to marshal encrypted data to JSON: %s", err)
			}
			privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, string(keyStorePassword))
			if err != nil {
				return nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
			}
			err = os.WriteFile(privKeyPath, encryptedRSAJSON, 0o644)
			if err != nil {
				return nil, err
			}
		} else if err == nil {
			return crypto.ReadEncryptedRSAKey(privKeyPath, privKeyPassPath)
		}
	} else {
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(privKeyPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("🔑 private key file: %s", err)
		}
		if _, err := os.Stat(privKeyPassPath); os.IsNotExist(err) {
			return nil, fmt.Errorf("🔑 password file: %s", err)
		}
		return crypto.ReadEncryptedRSAKey(privKeyPath, privKeyPassPath)
	}
	return privateKey, nil
}

func WriteInitResults(depositDataArr []*initiator.DepositDataJson, keySharesArr []*initiator.KeyShares, nonces []uint64, ids [][24]byte, ceremonySigsArr []*initiator.CeremonySigs, logger *zap.Logger) {
	if len(depositDataArr) != int(Validators) || len(keySharesArr) != int(Validators) {
		logger.Fatal("Incoming result arrays have inconsistent length")
	}
	timestamp := time.Now().Format(time.RFC3339)
	dir := fmt.Sprintf("%s/ceremony-%s", OutputPath, timestamp)
	err := os.Mkdir(dir, os.ModePerm)
	if err != nil {
		logger.Fatal("Failed to create a ceremony directory: ", zap.Error(err))
	}
	for i := 0; i < int(Validators); i++ {
		nestedDir := fmt.Sprintf("%s/0x%s", dir, depositDataArr[i].PubKey)
		err := os.Mkdir(nestedDir, os.ModePerm)
		if err != nil {
			logger.Fatal("Failed to create a validator key directory: ", zap.Error(err))
		}
		logger.Info("💾 Writing deposit data json to file", zap.String("path", nestedDir))
		err = WriteDepositResult(depositDataArr[i], nestedDir)
		if err != nil {
			logger.Fatal("Failed writing deposit data file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("deposit", depositDataArr[i]))
		}
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", nestedDir))
		err = WriteKeysharesResult(keySharesArr[i], nestedDir, ids[i])
		if err != nil {
			logger.Fatal("Failed writing keyshares file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("deposit", keySharesArr[i]))
		}
		err = WriteCeremonySigs(ceremonySigsArr[i], nestedDir, ids[i])
		if err != nil {
			logger.Fatal("Failed writing ceremony sig file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("sigs", ceremonySigsArr[i]))
		}
	}
	if Validators > 1 {
		// Write all to one JSON file
		depositFinalPath := fmt.Sprintf("%s/deposit_data.json", dir)
		logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
		err := utils.WriteJSON(depositFinalPath, depositDataArr)
		if err != nil {
			logger.Fatal("Failed writing deposit data file: ", zap.Error(err), zap.String("path", depositFinalPath), zap.Any("deposits", depositDataArr))
		}
		keysharesFinalPath := fmt.Sprintf("%s/keyshares.json", dir)
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
		err = utils.WriteJSON(keysharesFinalPath, initiator.GenerateAggregatesKeyshares(keySharesArr))
		if err != nil {
			logger.Fatal("Failed writing keyshares to file: ", zap.Error(err), zap.String("path", keysharesFinalPath), zap.Any("keyshares", keySharesArr))
		}
	}
}

func WriteKeysharesResult(keyShares *initiator.KeyShares, dir string, id [24]byte) error {
	keysharesFinalPath := fmt.Sprintf("%s/keyshares-%s-%s-%d-%s.json", dir, keyShares.Shares[0].Payload.PublicKey, keyShares.Shares[0].OwnerAddress, keyShares.Shares[0].OwnerNonce, hex.EncodeToString(id[:]))
	err := utils.WriteJSON(keysharesFinalPath, keyShares)
	if err != nil {
		return fmt.Errorf("failed writing keyshares file: %w, %v", err, keyShares)
	}
	return nil
}

func WriteDepositResult(depositData *initiator.DepositDataJson, dir string) error {
	depositFinalPath := fmt.Sprintf("%s/deposit_data-0x%s.json", dir, depositData.PubKey)
	err := utils.WriteJSON(depositFinalPath, []*initiator.DepositDataJson{depositData})
	if err != nil {
		return fmt.Errorf("failed writing deposit data file: %w, %v", err, depositData)
	}
	return nil
}

func WriteInstanceID(dir string, id [24]byte) error {
	instanceIdPath := fmt.Sprintf("%s/instance_id.json", dir)
	err := utils.WriteJSON(instanceIdPath, hex.EncodeToString(id[:]))
	if err != nil {
		return fmt.Errorf("failed writing instance ID file: %w, %s", err, hex.EncodeToString(id[:]))
	}
	return nil
}

func WriteCeremonySigs(ceremonySigs *initiator.CeremonySigs, dir string, id [24]byte) error {
	finalPath := fmt.Sprintf("%s/ceremony_sigs-%s.json", dir, hex.EncodeToString(id[:]))
	err := utils.WriteJSON(finalPath, ceremonySigs)
	if err != nil {
		return fmt.Errorf("failed writing data file: %w, %v", err, ceremonySigs)
	}
	return nil
}
