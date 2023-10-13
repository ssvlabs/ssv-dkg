package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Flag names.
const (
	threshold                = "threshold"
	withdrawAddress          = "withdrawAddress"
	operatorIDs              = "operatorIDs"
	operatorsInfo            = "operatorsInfo"
	operatorsInfoPath        = "operatorsInfoPath"
	operatorPrivKey          = "privKey"
	configPath               = "configPath"
	initiatorPrivKey         = "initiatorPrivKey"
	initiatorPrivKeyPassword = "initiatorPrivKeyPassword"
	generateInitiatorKey     = "generateInitiatorKey"
	operatorPort             = "port"
	owner                    = "owner"
	nonce                    = "nonce"
	network                  = "network"
	mnemonicFlag             = "mnemonic"
	indexFlag                = "index"
	password                 = "password"
	outputPath               = "outputPath"
	storeShare               = "storeShare"
	logLevel                 = "logLevel"
	logFormat                = "logFormat"
	logLevelFormat           = "logLevelFormat"
	logFilePath              = "logFilePath"
)

// ThresholdFlag adds threshold flag to the command
func ThresholdFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, threshold, 0, "Threshold for distributed signature", false)
}

// GetThresholdFlagValue gets threshold flag from the command
func GetThresholdFlagValue(c *cobra.Command) (uint64, error) {
	return c.Flags().GetUint64(threshold)
}

// WithdrawAddressFlag  adds withdraw address flag to the command
func WithdrawAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, withdrawAddress, "", "Withdrawal address", false)
}

// GetWithdrawAddressFlagValue gets withdraw address flag from the command
func GetWithdrawAddressFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(withdrawAddress)
}

// operatorIDsFlag adds operators IDs flag to the command
func OperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, operatorIDs, []string{"1", "2", "3"}, "Operator IDs", false)
}

// GetThresholdFlagValue gets operators IDs flag from the command
func GetoperatorIDsFlagValue(c *cobra.Command) ([]string, error) {
	return c.Flags().GetStringSlice(operatorIDs)
}

// OperatorsInfoFlag  adds path to operators' ifo file flag to the command
func OperatorsInfoFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorsInfo, "", "Raw JSON string operators' public keys, IDs and IPs file e.g. `{ 1: { publicKey: XXX, id: 1, ip: 10.0.0.1:3033 }`", false)
}

// GetOperatorsInfoFlagValue gets path to operators' ifo file flag from the command
func GetOperatorsInfoFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(operatorsInfo)
}

// OperatorsInfoFlag  adds path to where to look for operator info file flag to the command
func OperatorsInfoPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorsInfoPath, "", "Path to where to look for operator info file", false)
}

// GetOperatorsInfoPathFlagValue gets path to where to look for operator info file flag from the command
func GetOperatorsInfoPathFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(operatorsInfoPath)
}

// OwnerAddressFlag  adds owner address flag to the command
func OwnerAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, owner, "", "Owner address", false)
}

// GetOwnerAddressFlagValue gets owner address flag from the command
func GetOwnerAddressFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(owner)
}

// NonceFlag  owner nonce flag to the command
func NonceFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, nonce, 0, "Owner nonce", false)
}

// GetNonceFlagValue gets owner nonce flag from the command
func GetNonceFlagValue(c *cobra.Command) (uint64, error) {
	return c.Flags().GetUint64(nonce)
}

// NetworkFlag  adds the fork version of the network flag to the command
func NetworkFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, network, "mainnet", "Network name: mainnet, prater, or now_test_network", false)
}

// OperatorPrivateKeyFlag  adds private key flag to the command
func InitiatorPrivateKeyFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, initiatorPrivKey, "", "Path to initiator Private Key file", false)
}

// GetOperatorPrivateKeyFlagValue gets private key flag from the command
func GetInitiatorPrivateKeyFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(initiatorPrivKey)
}

// GenerateInitiatorKeyFlag adds flag to generate a random secure password and initiator RSA key pair encrypted with this password
func GenerateInitiatorKeyFlag(c *cobra.Command) {
	AddPersistentBoolFlag(c, generateInitiatorKey, false, "Generates a random secure password and initiator RSA key pair encrypted with this password", false)
}

// GetGenerateInitiatorKeyFlagValue gets flag to generate a random secure password and initiator RSA key pair encrypted with this password
func GetGenerateInitiatorKeyFlagValue(c *cobra.Command) (bool, error) {
	return c.Flags().GetBool(generateInitiatorKey)
}

// OperatorPrivateKeyPassFlag  adds private key flag to the command
func InitiatorPrivateKeyPassFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, initiatorPrivKeyPassword, "", "Password to decrypt initiator`s Private Key file", false)
}

// GetOperatorPrivateKeyFlagValue gets private key flag from the command
func GetInitiatorPrivateKeyPassFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(initiatorPrivKeyPassword)
}

// OperatorPrivateKeyFlag  adds private key flag to the command
func OperatorPrivateKeyFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorPrivKey, "", "Path to initiator Private Key file", false)
}

// GetOperatorPrivateKeyFlagValue gets private key flag from the command
func GetOperatorPrivateKeyFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(operatorPrivKey)
}

// OperatorPrivateKeyPassFlag  adds private key flag to the command
func OperatorPrivateKeyPassFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, password, "", "Password to decrypt operator Private Key file", false)
}

// GetOperatorPrivateKeyFlagValue gets private key flag from the command
func GetOperatorPrivateKeyPassFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(password)
}

// OperatorPortFlag  adds operator listening port flag to the command
func OperatorPortFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, operatorPort, 3030, "Operator Private Key hex", false)
}

// OperatorConfigPathFlag config path flag to the command
func ConfigPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, configPath, "", "Path to config file", false)
}

// GetConfigPathFlagValue gets config path flag from the command
func GetConfigPathFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(configPath)
}

// GetOperatorPortFlagValue gets operator listening port flag from the command
func GetOperatorPortFlagValue(c *cobra.Command) (uint64, error) {
	return c.Flags().GetUint64(operatorPort)
}

// LogLevelFlag logger's log level flag to the command
func LogLevelFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logLevel, "debug", "Defines logger's log level", false)
}

// GetLogLevelFlagValue gets logger's log level flag from the command
func GetLogLevelFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(logLevel)
}

// LogFormatFlag logger's  logger's encoding flag to the command
func LogFormatFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logFormat, "json", "Defines logger's encoding, valid values are 'json' (default) and 'console'", false)
}

// GetLogFormatFlagValue gets logger's encoding flag from the command
func GetLogFormatFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(logFormat)
}

// LogLevelFormatFlag logger's level format flag to the command
func LogLevelFormatFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logLevelFormat, "capitalColor", "Defines logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase'", false)
}

// GetLogLevelFormatFlagValue gets logger's level format flag from the command
func GetLogLevelFormatFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(logLevelFormat)
}

// LogFilePathFlag file path to write logs into
func LogFilePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logFilePath, "./data/debug.log", "Defines a file path to write logs into", false)
}

// GetLogFilePathValue gets logs file path flag from the command
func GetLogFilePathValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(logFilePath)
}

// AddPersistentStringFlag adds a string flag to the command
func AddPersistentStringFlag(c *cobra.Command, flag string, value string, description string, isRequired bool) {
	req := ""
	if isRequired {
		req = " (required)"
	}

	c.PersistentFlags().String(flag, value, fmt.Sprintf("%s%s", description, req))

	if isRequired {
		_ = c.MarkPersistentFlagRequired(flag)
	}
}

// AddPersistentIntFlag adds a int flag to the command
func AddPersistentIntFlag(c *cobra.Command, flag string, value uint64, description string, isRequired bool) {
	req := ""
	if isRequired {
		req = " (required)"
	}

	c.PersistentFlags().Uint64(flag, value, fmt.Sprintf("%s%s", description, req))

	if isRequired {
		_ = c.MarkPersistentFlagRequired(flag)
	}
}

// AddPersistentStringArrayFlag adds a string array flag to the command
func AddPersistentStringArrayFlag(c *cobra.Command, flag string, value []string, description string, isRequired bool) {
	req := ""
	if isRequired {
		req = " (required)"
	}

	c.PersistentFlags().StringArray(flag, value, fmt.Sprintf("%s%s", description, req))

	if isRequired {
		_ = c.MarkPersistentFlagRequired(flag)
	}
}

// AddPersistentStringArrayFlag adds a string slice flag to the command
func AddPersistentStringSliceFlag(c *cobra.Command, flag string, value []string, description string, isRequired bool) {
	req := ""
	if isRequired {
		req = " (required)"
	}

	c.PersistentFlags().StringSlice(flag, value, fmt.Sprintf("%s%s", description, req))

	if isRequired {
		_ = c.MarkPersistentFlagRequired(flag)
	}
}

// AddPersistentIntFlag adds a int flag to the command
func AddPersistentBoolFlag(c *cobra.Command, flag string, value bool, description string, isRequired bool) {
	req := ""
	if isRequired {
		req = " (required)"
	}

	c.PersistentFlags().Bool(flag, value, fmt.Sprintf("%s%s", description, req))

	if isRequired {
		_ = c.MarkPersistentFlagRequired(flag)
	}
}

// AddMnemonicFlag adds the mnemonic key flag to the command
func AddMnemonicFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, mnemonicFlag, "", "24 letter mnemonic phrase", true)
}

// GetMnemonicFlagValue gets the mnemonic key flag from the command
func GetMnemonicFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(mnemonicFlag)
}

// AddKeyIndexFlag adds the key index flag to the command
func AddKeyIndexFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, indexFlag, 0, "Index of the key to export from mnemonic", false)
}

// GetKeyIndexFlagValue gets the key index flag to the command
func GetKeyIndexFlagValue(c *cobra.Command) (uint64, error) {
	return c.Flags().GetUint64(indexFlag)
}

func ResultPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, outputPath, "./", "Path to store results", false)
}

func GetResultPathFlag(c *cobra.Command) (string, error) {
	return c.Flags().GetString(outputPath)
}

func StoreShareFlag(c *cobra.Command) {
	AddPersistentBoolFlag(c, storeShare, false, "Store BLS share as json", false)
}

func GetStoreShareFlag(c *cobra.Command) (bool, error) {
	return c.Flags().GetBool(storeShare)
}
