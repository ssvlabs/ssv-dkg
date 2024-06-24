package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
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
	OperatorsInfo     string
	OperatorsInfoPath string
	OperatorIDs       []string
	WithdrawAddress   common.Address
	Network           string
	OwnerAddress      common.Address
	Nonce             uint64
	Validators        uint
	ClientCACertPath  []string
)

// operator flags
var (
	PrivKey           string
	PrivKeyPassword   string
	Port              uint64
	OperatorID        uint64
	ServerTLSCertPath string
	ServerTLSKeyPath  string
	EthEndpointURL    string
)

// verify flags
var (
	CeremonyDir string
)

// resigning/reshare flags
var (
	ProofsFilePath         string
	NewOperatorIDs         []string
	KeystorePath           string
	KeystorePass           string
)

// SetViperConfig reads a yaml config file if provided
func SetViperConfig(cmd *cobra.Command) error {
	if err := viper.BindPFlag("configPath", cmd.PersistentFlags().Lookup("configPath")); err != nil {
		return err
	}
	ConfigPath = viper.GetString("configPath")
	if ConfigPath != "" {
		if strings.Contains(ConfigPath, "../") {
			return fmt.Errorf("😥 configPath should not contain traversal")
		}
		stat, err := os.Stat(ConfigPath)
		if err != nil {
			return err
		}
		if stat.IsDir() {
			return fmt.Errorf("configPath flag should be a path to a *.yaml file, but dir provided")
		}
		viper.SetConfigType("yaml")
		viper.SetConfigFile(ConfigPath)
		if err := viper.ReadInConfig(); err != nil {
			return err
		}
	}
	return nil
}

// SetGlobalLogger creates a logger
func SetGlobalLogger(cmd *cobra.Command, name string) (*zap.Logger, error) {
	// If the log file doesn't exist, create it
	_, err := os.OpenFile(filepath.Clean(LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
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
func OpenPrivateKey(passwordFilePath, privKeyPath string) (*rsa.PrivateKey, error) {
	// check if a password string a valid path, then read password from the file
	if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("😥 Password file doesn`t exist: %s", err)
	}
	encryptedRSAJSON, err := os.ReadFile(filepath.Clean(privKeyPath))
	if err != nil {
		return nil, fmt.Errorf("😥 Cant read operator's key file: %s", err)
	}
	keyStorePassword, err := os.ReadFile(filepath.Clean(passwordFilePath))
	if err != nil {
		return nil, fmt.Errorf("😥 Error reading password file: %s", err)
	}
	privateKey, err := crypto.DecryptRSAKeystore(encryptedRSAJSON, string(keyStorePassword))
	if err != nil {
		return nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
	}
	return privateKey, nil
}

// ReadOperatorsInfoFile reads operators data from path
func ReadOperatorsInfoFile(operatorsInfoPath string, logger *zap.Logger) (wire.OperatorsCLI, error) {
	fmt.Printf("📖 looking operators info 'operators_info.json' file: %s \n", operatorsInfoPath)
	_, err := os.Stat(operatorsInfoPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
	}
	logger.Info("📖 reading operators info JSON file")
	operatorsInfoJSON, err := os.ReadFile(filepath.Clean(operatorsInfoPath))
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
	}
	var operators wire.OperatorsCLI
	err = json.Unmarshal(operatorsInfoJSON, &operators)
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to load operators: %s", err)
	}
	return operators, nil
}

func SetBaseFlags(cmd *cobra.Command) {
	flags.ResultPathFlag(cmd)
	flags.ConfigPathFlag(cmd)
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
	flags.WithdrawAddressFlag(cmd)
	flags.ValidatorsFlag(cmd)
	flags.ClientCACertPathFlag(cmd)
}

func SetOperatorFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.PrivateKeyFlag(cmd)
	flags.PrivateKeyPassFlag(cmd)
	flags.OperatorPortFlag(cmd)
	flags.OperatorIDFlag(cmd)
	flags.ServerTLSCertPath(cmd)
	flags.ServerTLSKeyPath(cmd)
	flags.EthEndpointURL(cmd)
}

func SetVerifyFlags(cmd *cobra.Command) {
	flags.AddPersistentStringFlag(cmd, "ceremonyDir", "", "Path to the ceremony directory", true)
	flags.AddPersistentIntFlag(cmd, "validators", 1, "Number of validators", true)
	flags.AddPersistentStringFlag(cmd, "withdrawAddress", "", "Withdrawal address", true)
	flags.AddPersistentIntFlag(cmd, "nonce", 0, "Owner nonce", true)
	flags.AddPersistentStringFlag(cmd, "owner", "", "Owner address", true)
}

func SetResigningFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.OperatorsInfoFlag(cmd)
	flags.OperatorsInfoPathFlag(cmd)
	flags.OperatorIDsFlag(cmd)
	flags.OwnerAddressFlag(cmd)
	flags.NonceFlag(cmd)
	flags.NetworkFlag(cmd)
	flags.WithdrawAddressFlag(cmd)
	flags.ProofsFilePath(cmd)
	flags.ClientCACertPathFlag(cmd)
	flags.KeystoreFilePath(cmd)
	flags.KeystoreFilePass(cmd)
	flags.EthEndpointURL(cmd)
}

func SetReshareFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	flags.OperatorsInfoFlag(cmd)
	flags.OperatorsInfoPathFlag(cmd)
	flags.OperatorIDsFlag(cmd)
	flags.NewOperatorIDsFlag(cmd)
	flags.WithdrawAddressFlag(cmd)
	flags.OwnerAddressFlag(cmd)
	flags.NonceFlag(cmd)
	flags.NetworkFlag(cmd)
	flags.ProofsFilePath(cmd)
	flags.ClientCACertPathFlag(cmd)
	flags.KeystoreFilePath(cmd)
	flags.KeystoreFilePass(cmd)
	flags.EthEndpointURL(cmd)
}

func SetHealthCheckFlags(cmd *cobra.Command) {
	flags.AddPersistentStringSliceFlag(cmd, "ip", []string{}, "Operator ip:port", true)
}

// BindFlags binds flags to yaml config parameters
func BindBaseFlags(cmd *cobra.Command) error {
	if err := viper.BindPFlag("outputPath", cmd.PersistentFlags().Lookup("outputPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("configPath", cmd.PersistentFlags().Lookup("configPath")); err != nil {
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
	if strings.Contains(OutputPath, "../") {
		return fmt.Errorf("😥 outputPath should not contain traversal")
	}
	if err := createDirIfNotExist(OutputPath); err != nil {
		return err
	}
	LogLevel = viper.GetString("logLevel")
	LogFormat = viper.GetString("logFormat")
	LogLevelFormat = viper.GetString("logLevelFormat")
	LogFilePath = viper.GetString("logFilePath")
	if strings.Contains(LogFilePath, "../") {
		return fmt.Errorf("😥 logFilePath should not contain traversal")
	}
	return nil
}

// BindInitiatorBaseFlags binds flags to yaml config parameters
func BindInitiatorBaseFlags(cmd *cobra.Command) error {
	var err error
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorIDs", cmd.PersistentFlags().Lookup("operatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfo", cmd.PersistentFlags().Lookup("operatorsInfo")); err != nil {
		return err
	}
	if err := viper.BindPFlag("owner", cmd.PersistentFlags().Lookup("owner")); err != nil {
		return err
	}
	if err := viper.BindPFlag("nonce", cmd.PersistentFlags().Lookup("nonce")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfoPath", cmd.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("clientCACertPath", cmd.PersistentFlags().Lookup("clientCACertPath")); err != nil {
		return err
	}
	OperatorIDs = viper.GetStringSlice("operatorIDs")
	if len(OperatorIDs) == 0 {
		return fmt.Errorf("😥 Operator IDs flag cant be empty")
	}
	OperatorsInfoPath = viper.GetString("operatorsInfoPath")
	if strings.Contains(OperatorsInfoPath, "../") {
		return fmt.Errorf("😥 operatorsInfoPath flag should not contain traversal")
	}
	OperatorsInfo = viper.GetString("operatorsInfo")
	if OperatorsInfoPath != "" && OperatorsInfo != "" {
		return fmt.Errorf("😥 operators info can be provided either as a raw JSON string, or path to a file, not both")
	}
	if OperatorsInfoPath == "" && OperatorsInfo == "" {
		return fmt.Errorf("😥 operators info should be provided either as a raw JSON string, or path to a file")
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
	ClientCACertPath = viper.GetStringSlice("clientCACertPath")
	for _, certPath := range ClientCACertPath {
		if strings.Contains(certPath, "../") {
			return fmt.Errorf("😥 clientCACertPath flag should not contain traversal")
		}
	}
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
	Validators = viper.GetUint("validators")
	if Validators > 100 || Validators == 0 {
		return fmt.Errorf("🚨 Amount of generated validators should be 1 to 100")
	}
	return nil
}

// BindResigningFlags binds flags to yaml config parameters for the resigning of previous DKG result
func BindResigningFlags(cmd *cobra.Command) error {
	if err := BindBaseFlags(cmd); err != nil {
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
	if err := viper.BindPFlag("clientCACertPath", cmd.PersistentFlags().Lookup("clientCACertPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("proofsFilePath", cmd.PersistentFlags().Lookup("proofsFilePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorIDs", cmd.PersistentFlags().Lookup("operatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("withdrawAddress", cmd.PersistentFlags().Lookup("withdrawAddress")); err != nil {
		return err
	}
	if err := viper.BindPFlag("network", cmd.Flags().Lookup("network")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ethKeystorePath", cmd.PersistentFlags().Lookup("ethKeystorePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ethKeystorePass", cmd.PersistentFlags().Lookup("ethKeystorePass")); err != nil {
		return err
	}
	OperatorIDs = viper.GetStringSlice("operatorIDs")
	if len(OperatorIDs) == 0 {
		return fmt.Errorf("😥 Operator IDs flag cant be empty")
	}
	OperatorsInfoPath = viper.GetString("operatorsInfoPath")
	if strings.Contains(OperatorsInfoPath, "../") {
		return fmt.Errorf("😥 operatorsInfoPath flag should not contain traversal")
	}
	OperatorsInfo = viper.GetString("operatorsInfo")
	if OperatorsInfoPath != "" && OperatorsInfo != "" {
		return fmt.Errorf("😥 operators info can be provided either as a raw JSON string, or path to a file, not both")
	}
	if OperatorsInfoPath == "" && OperatorsInfo == "" {
		return fmt.Errorf("😥 operators info should be provided either as a raw JSON string, or path to a file")
	}
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 Failed to get owner address flag value")
	}
	Nonce = viper.GetUint64("nonce")
	ClientCACertPath = viper.GetStringSlice("clientCACertPath")
	for _, certPath := range ClientCACertPath {
		if strings.Contains(certPath, "../") {
			return fmt.Errorf("😥 clientCACertPath flag should not contain traversal")
		}
	}
	ProofsFilePath = viper.GetString("proofsFilePath")
	if ProofsFilePath == "" {
		return fmt.Errorf("😥 Failed to get path to proofs flag value")
	}
	if strings.Contains(ProofsFilePath, "../") {
		return fmt.Errorf("😥 proofsFilePath flag should not contain traversal")
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
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 Failed to parse owner address: %s", err)
	}
	KeystorePath = viper.GetString("ethKeystorePath")
	if strings.Contains(KeystorePath, "../") {
		return fmt.Errorf("😥 ethKeystorePath should not contain traversal")
	}
	KeystorePass = viper.GetString("ethKeystorePass")
	if strings.Contains(KeystorePath, "../") {
		return fmt.Errorf("😥 ethKeystorePass should not contain traversal")
	}
	return nil
}

// BindReshareFlags binds flags to yaml config parameters for the resharing ceremony of DKG
func BindReshareFlags(cmd *cobra.Command) error {
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfo", cmd.PersistentFlags().Lookup("operatorsInfo")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorsInfoPath", cmd.PersistentFlags().Lookup("operatorsInfoPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorIDs", cmd.PersistentFlags().Lookup("operatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("newOperatorIDs", cmd.PersistentFlags().Lookup("newOperatorIDs")); err != nil {
		return err
	}
	if err := viper.BindPFlag("clientCACertPath", cmd.PersistentFlags().Lookup("clientCACertPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("withdrawAddress", cmd.PersistentFlags().Lookup("withdrawAddress")); err != nil {
		return err
	}
	if err := viper.BindPFlag("network", cmd.Flags().Lookup("network")); err != nil {
		return err
	}
	if err := viper.BindPFlag("owner", cmd.PersistentFlags().Lookup("owner")); err != nil {
		return err
	}
	if err := viper.BindPFlag("nonce", cmd.PersistentFlags().Lookup("nonce")); err != nil {
		return err
	}
	if err := viper.BindPFlag("proofsFilePath", cmd.PersistentFlags().Lookup("proofsFilePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ethKeystorePath", cmd.PersistentFlags().Lookup("ethKeystorePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ethKeystorePass", cmd.PersistentFlags().Lookup("ethKeystorePass")); err != nil {
		return err
	}
	OperatorsInfoPath = viper.GetString("operatorsInfoPath")
	if strings.Contains(OperatorsInfoPath, "../") {
		return fmt.Errorf("😥 logFilePath should not contain traversal")
	}
	OperatorsInfo = viper.GetString("operatorsInfo")
	if OperatorsInfoPath != "" && OperatorsInfo != "" {
		return fmt.Errorf("😥 operators info can be provided either as a raw JSON string, or path to a file, not both")
	}
	if OperatorsInfoPath == "" && OperatorsInfo == "" {
		return fmt.Errorf("😥 operators info should be provided either as a raw JSON string, or path to a file")
	}
	OperatorIDs = viper.GetStringSlice("operatorIDs")
	if len(OperatorIDs) == 0 {
		return fmt.Errorf("😥 Old operator IDs flag cannot be empty")
	}
	NewOperatorIDs = viper.GetStringSlice("newOperatorIDs")
	if len(NewOperatorIDs) == 0 {
		return fmt.Errorf("😥 New operator IDs flag cannot be empty")
	}
	ProofsFilePath = viper.GetString("proofsFilePath")
	if ProofsFilePath == "" {
		return fmt.Errorf("😥 Failed to get path to proofs flag value")
	}
	if strings.Contains(ProofsFilePath, "../") {
		return fmt.Errorf("😥 proofsFilePath flag should not contain traversal")
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
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 Failed to get owner address flag value")
	}
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 Failed to parse owner address: %s", err)
	}
	Nonce = viper.GetUint64("nonce")
	ClientCACertPath = viper.GetStringSlice("clientCACertPath")
	for _, certPath := range ClientCACertPath {
		if strings.Contains(certPath, "../") {
			return fmt.Errorf("😥 clientCACertPath flag should not contain traversal")
		}
	}
	KeystorePath = viper.GetString("ethKeystorePath")
	if strings.Contains(KeystorePath, "../") {
		return fmt.Errorf("😥 ethKeystorePath should not contain traversal")
	}
	KeystorePass = viper.GetString("ethKeystorePass")
	if strings.Contains(KeystorePath, "../") {
		return fmt.Errorf("😥 ethKeystorePass should not contain traversal")
	}
	return nil
}

// BindOperatorFlags binds flags to yaml config parameters for the operator
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
	if err := viper.BindPFlag("serverTLSCertPath", cmd.PersistentFlags().Lookup("serverTLSCertPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("serverTLSKeyPath", cmd.PersistentFlags().Lookup("serverTLSKeyPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ethEndpointURL", cmd.PersistentFlags().Lookup("ethEndpointURL")); err != nil {
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
	ServerTLSCertPath = viper.GetString("serverTLSCertPath")
	if ServerTLSCertPath == "" {
		return fmt.Errorf("😥 Failed to get serverTLSCertPath flag value")
	}
	if strings.Contains(ServerTLSCertPath, "../") {
		return fmt.Errorf("😥 serverTLSCertPath flag should not contain traversal")
	}
	ServerTLSKeyPath = viper.GetString("serverTLSKeyPath")
	if ServerTLSKeyPath == "" {
		return fmt.Errorf("😥 Failed to get serverTLSKeyPath flag value")
	}
	if strings.Contains(ServerTLSKeyPath, "../") {
		return fmt.Errorf("😥 serverTLSKeyPath flag should not contain traversal")
	}
	EthEndpointURL = viper.GetString("ethEndpointURL")
	if !IsUrl(EthEndpointURL) {
		return fmt.Errorf("ethereum endpoint URL: %s - Invalid", EthEndpointURL)
	}
	return nil
}

// BindVerifyFlags binds flags to yaml config parameters for the verification
func BindVerifyFlags(cmd *cobra.Command) error {
	if err := viper.BindPFlag("ceremonyDir", cmd.PersistentFlags().Lookup("ceremonyDir")); err != nil {
		return err
	}
	if err := viper.BindPFlag("validators", cmd.Flags().Lookup("validators")); err != nil {
		return err
	}
	if err := viper.BindPFlag("withdrawAddress", cmd.PersistentFlags().Lookup("withdrawAddress")); err != nil {
		return err
	}
	if err := viper.BindPFlag("nonce", cmd.PersistentFlags().Lookup("nonce")); err != nil {
		return err
	}
	if err := viper.BindPFlag("owner", cmd.PersistentFlags().Lookup("owner")); err != nil {
		return err
	}
	CeremonyDir = viper.GetString("ceremonyDir")
	if CeremonyDir == "" {
		return fmt.Errorf("😥 Failed to get ceremony directory flag value")
	}
	if strings.Contains(CeremonyDir, "../") {
		return fmt.Errorf("😥 CeremonyDir should not contain traversal")
	}
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 Failed to get owner address flag value")
	}
	var err error
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 Failed to parse owner address: %s", err)
	}
	Nonce = viper.GetUint64("nonce")
	WithdrawAddress, err = utils.HexToAddress(viper.GetString("withdrawAddress"))
	if err != nil {
		return fmt.Errorf("😥 Failed to parse withdraw address: %s", err)
	}
	Validators = viper.GetUint("validators")
	if Validators == 0 {
		return fmt.Errorf("😥 Failed to get validators flag value")
	}
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
	// sort array
	sort.SliceStable(partsarr, func(i, j int) bool {
		return partsarr[i] < partsarr[j]
	})
	sorted := sort.SliceIsSorted(partsarr, func(p, q int) bool {
		return partsarr[p] < partsarr[q]
	})
	if !sorted {
		return nil, fmt.Errorf("slice isnt sorted")
	}
	return partsarr, nil
}

// LoadOperators loads operators data from raw json or file path
func LoadOperators(logger *zap.Logger) (wire.OperatorsCLI, error) {
	var operators wire.OperatorsCLI
	var err error
	if OperatorsInfo != "" {
		err = json.Unmarshal([]byte(OperatorsInfo), &operators)
		if err != nil {
			return nil, err
		}
	} else {
		operators, err = ReadOperatorsInfoFile(OperatorsInfoPath, logger)
		if err != nil {
			return nil, err
		}
	}
	if operators == nil {
		return nil, fmt.Errorf("no information about operators is provided. Please use or raw JSON, or file")
	}
	// check that we use https
	if err := checkIfOperatorHTTPS(operators); err != nil {
		return nil, err
	}
	return operators, nil
}

func WriteResults(
	logger *zap.Logger,
	depositDataArr []*wire.DepositDataCLI,
	keySharesArr []*wire.KeySharesCLI,
	proofs [][]*wire.SignedProof,
	withRandomness bool,
	expectedValidatorCount int,
	expectedOwnerAddress common.Address,
	expectedOwnerNonce uint64,
	expectedWithdrawAddress common.Address,
	outputPath string,
) (err error) {
	if expectedValidatorCount == 0 {
		return fmt.Errorf("expectedValidatorCount is 0")
	}
	if len(depositDataArr) != len(keySharesArr) || len(depositDataArr) != len(proofs) {
		return fmt.Errorf("Incoming result arrays have inconsistent length")
	}
	if len(depositDataArr) == 0 {
		return fmt.Errorf("no results to write")
	}
	if len(depositDataArr) != int(expectedValidatorCount) {
		return fmt.Errorf("expectedValidatorCount is not equal to the length of given results")
	}

	// order the keyshares by nonce
	sort.SliceStable(keySharesArr, func(i, j int) bool {
		return keySharesArr[i].Shares[0].ShareData.OwnerNonce < keySharesArr[j].Shares[0].ShareData.OwnerNonce
	})
	sorted := sort.SliceIsSorted(keySharesArr, func(p, q int) bool {
		return keySharesArr[p].Shares[0].ShareData.OwnerNonce < keySharesArr[q].Shares[0].ShareData.OwnerNonce
	})
	if !sorted {
		return fmt.Errorf("slice is not sorted")
	}

	// check if public keys are unique
	for i := 0; i < len(keySharesArr)-1; i++ {
		pk1 := keySharesArr[i].Shares[0].Payload.PublicKey
		pk2 := keySharesArr[i+1].Shares[0].Payload.PublicKey
		if pk1 == pk2 {
			return fmt.Errorf("public key %s is not unique", keySharesArr[i].Shares[0].Payload.PublicKey)
		}
	}

	// order deposit data and proofs to match keyshares order
	sortedDepositData := make([]*wire.DepositDataCLI, len(depositDataArr))
	sortedProofs := make([][]*wire.SignedProof, len(depositDataArr))
	for i, keyshare := range keySharesArr {
		pk := strings.TrimPrefix(keyshare.Shares[0].Payload.PublicKey, "0x")
		for _, deposit := range depositDataArr {
			if deposit.PubKey == pk {
				sortedDepositData[i] = deposit
				break
			}
		}
		if sortedDepositData[i] == nil {
			return fmt.Errorf("failed to match deposit data with keyshares")
		}
		for _, proof := range proofs {
			if hex.EncodeToString(proof[0].Proof.ValidatorPubKey) == pk {
				sortedProofs[i] = proof
				break
			}
		}
		if sortedProofs[i] == nil {
			return fmt.Errorf("failed to match proofs with keyshares")
		}
	}
	depositDataArr = sortedDepositData
	proofs = sortedProofs

	// Validate the results.
	aggregatedKeyshares := &wire.KeySharesCLI{
		Version:   keySharesArr[0].Version,
		CreatedAt: keySharesArr[0].CreatedAt,
	}
	for i := 0; i < len(keySharesArr); i++ {
		aggregatedKeyshares.Shares = append(aggregatedKeyshares.Shares, keySharesArr[i].Shares...)
	}
	if err := validator.ValidateResults(depositDataArr, aggregatedKeyshares, proofs, expectedValidatorCount, expectedOwnerAddress, expectedOwnerNonce, expectedWithdrawAddress); err != nil {
		return err
	}

	// Create the ceremony directory.
	timestamp := time.Now().UTC().Format("2006-01-02--15-04-05.000")
	dirName := fmt.Sprintf("ceremony-%s", timestamp)
	if withRandomness {
		randomness := make([]byte, 4)
		if _, err := rand.Read(randomness); err != nil {
			return fmt.Errorf("failed to generate randomness: %w", err)
		}
		dirName = fmt.Sprintf("%s--%x", dirName, randomness)
	}
	dir := filepath.Join(outputPath, dirName)
	err = os.Mkdir(dir, os.ModePerm)
	if os.IsExist(err) {
		return fmt.Errorf("ceremony directory already exists: %w", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create a ceremony directory: %w", err)
	}

	// If saving fails, create a "FAILED" file under the ceremony directory.
	defer func() {
		if err != nil {
			if err := os.WriteFile(filepath.Join(dir, "FAILED"), []byte(err.Error()), 0o600); err != nil {
				logger.Error("failed to write error file", zap.Error(err))
			}
		}
	}()

	for i := 0; i < len(depositDataArr); i++ {
		nestedDir := fmt.Sprintf("%s/%06d-0x%s", dir, keySharesArr[i].Shares[0].ShareData.OwnerNonce, depositDataArr[i].PubKey)
		err := os.Mkdir(nestedDir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create a validator key directory: %w", err)
		}
		logger.Info("💾 Writing deposit data json", zap.String("path", nestedDir))
		err = WriteDepositResult(depositDataArr[i], nestedDir)
		if err != nil {
			logger.Error("Failed writing deposit data file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("deposit", depositDataArr[i]))
			return fmt.Errorf("failed writing deposit data file: %w", err)
		}
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", nestedDir))
		err = WriteKeysharesResult(keySharesArr[i], nestedDir)
		if err != nil {
			logger.Error("Failed writing keyshares file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("deposit", keySharesArr[i]))
			return fmt.Errorf("failed writing keyshares file: %w", err)
		}
		logger.Info("💾 Writing proofs to file", zap.String("path", nestedDir))
		err = WriteProofs(proofs[i], nestedDir)
		if err != nil {
			logger.Error("Failed writing proofs file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("proof", proofs[i]))
			return fmt.Errorf("failed writing proofs file: %w", err)
		}
	}
	// if there is only one Validator, do not create summary files
	if expectedValidatorCount > 1 {
		err := WriteAggregatedInitResults(dir, depositDataArr, keySharesArr, proofs, logger)
		if err != nil {
			return fmt.Errorf("failed writing aggregated results: %w", err)
		}
	}

	err = validator.ValidateResultsDir(dir, expectedValidatorCount, expectedOwnerAddress, expectedOwnerNonce, expectedWithdrawAddress)
	if err != nil {
		return fmt.Errorf("failed validating results dir: %w", err)
	}

	return nil
}

func WriteAggregatedInitResults(dir string, depositDataArr []*wire.DepositDataCLI, keySharesArr []*wire.KeySharesCLI, proofs [][]*wire.SignedProof, logger *zap.Logger) error {
	// Write all to one JSON file
	depositFinalPath := fmt.Sprintf("%s/deposit_data.json", dir)
	logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
	err := utils.WriteJSON(depositFinalPath, depositDataArr)
	if err != nil {
		logger.Error("Failed writing deposit data file: ", zap.Error(err), zap.String("path", depositFinalPath), zap.Any("deposits", depositDataArr))
		return err
	}
	keysharesFinalPath := fmt.Sprintf("%s/keyshares.json", dir)
	logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
	aggrKeySharesArr, err := initiator.GenerateAggregatesKeyshares(keySharesArr)
	if err != nil {
		return err
	}
	err = utils.WriteJSON(keysharesFinalPath, aggrKeySharesArr)
	if err != nil {
		logger.Error("Failed writing keyshares to file: ", zap.Error(err), zap.String("path", keysharesFinalPath), zap.Any("keyshares", keySharesArr))
		return err
	}
	proofsFinalPath := fmt.Sprintf("%s/proofs.json", dir)
	err = utils.WriteJSON(proofsFinalPath, proofs)
	if err != nil {
		logger.Error("Failed writing ceremony sig file: ", zap.Error(err), zap.String("path", proofsFinalPath), zap.Any("proofs", proofs))
		return err
	}

	return nil
}

func WriteKeysharesResult(keyShares *wire.KeySharesCLI, dir string) error {
	keysharesFinalPath := fmt.Sprintf("%s/keyshares.json", dir)
	err := utils.WriteJSON(keysharesFinalPath, keyShares)
	if err != nil {
		return fmt.Errorf("failed writing keyshares file: %w, %v", err, keyShares)
	}
	return nil
}

func WriteDepositResult(depositData *wire.DepositDataCLI, dir string) error {
	depositFinalPath := fmt.Sprintf("%s/deposit_data.json", dir)
	err := utils.WriteJSON(depositFinalPath, []*wire.DepositDataCLI{depositData})

	if err != nil {
		return fmt.Errorf("failed writing deposit data file: %w, %v", err, depositData)
	}
	return nil
}

func WriteProofs(proofs []*wire.SignedProof, dir string) error {
	finalPath := fmt.Sprintf("%s/proofs.json", dir)
	err := utils.WriteJSON(finalPath, proofs)
	if err != nil {
		return fmt.Errorf("failed writing data file: %w, %v", err, proofs)
	}
	return nil
}

func createDirIfNotExist(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Directory does not exist, try to create it
			if err := os.MkdirAll(path, os.ModePerm); err != nil {
				// Failed to create the directory
				return fmt.Errorf("😥 can't create %s: %w", path, err)
			}
		} else {
			// Some other error occurred
			return fmt.Errorf("😥 %s", err)
		}
	}
	return nil
}

// Wrapper around zap.Sync() that ignores EINVAL errors.
//
// See: https://github.com/uber-go/zap/issues/1093#issuecomment-1120667285
func Sync(logger *zap.Logger) error {
	err := logger.Sync()
	if !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func checkIfOperatorHTTPS(ops []wire.OperatorCLI) error {
	for _, op := range ops {
		url, err := url.Parse(op.Addr)
		if err != nil {
			return fmt.Errorf("parsing IP address: %s, err: %w", op.Addr, err)
		}
		if url.Scheme != "https" {
			return fmt.Errorf("only HTTPS scheme is allowed at operator address %s, got: %s", op.Addr, url.Scheme)
		}
	}
	return nil
}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}
