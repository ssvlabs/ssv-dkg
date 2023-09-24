package flags

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

// Flag names.
const (
	threshold                = "threshold"
	withdrawAddress          = "withdrawAddress"
	operatorIDs              = "operatorIDs"
	operatorsInfo            = "operatorsInfoPath"
	operatorPrivKey          = "privKey"
	configPath               = "configPath"
	initiatorPrivKey         = "initiatorPrivKey"
	initiatorPrivKeyPassword = "initiatorPrivKeyPassword"
	operatorPort             = "port"
	owner                    = "owner"
	nonce                    = "nonce"
	fork                     = "fork"
	mnemonicFlag             = "mnemonic"
	indexFlag                = "index"
	networkFlag              = "network"
	password                 = "password"
	depositResultsPath       = "depositResultsPath"
	ssvPayloadResultsPath    = "ssvPayloadResultsPath"
	storeShare               = "storeShare"
	logLevel                 = "logLevel"
	logFormat                = "logFormat"
	logLevelFormat           = "logLevelFormat"
	logFilePath              = "logFilePath"
	DBPath                   = "DBPath"
	DBReporting              = "DBReporting"
	DBGCInterval             = "DBGCInterval"
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
	AddPersistentStringFlag(c, operatorsInfo, "", "Path to operators' public keys, IDs and IPs file", false)
}

// GetOperatorsInfoFlagValue gets path to operators' ifo file flag from the command
func GetOperatorsInfoFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(operatorsInfo)
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

// ForkVersionFlag  adds the fork version of the network flag to the command
func ForkVersionFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, fork, "", "Fork version 4 bytes in HEX, i.e. 0x0000000000", false)
}

// GetForkVersionFlagValue gets the fork version of the network flag from the command
func GetForkVersionFlagValue(c *cobra.Command) ([4]byte, string, error) {
	forkHex, err := c.Flags().GetString(fork)
	if err != nil {
		return [4]byte{}, "", err
	}
	forkBytes, err := hex.DecodeString(forkHex)
	if err != nil {
		return [4]byte{}, "", err
	}
	var fork [4]byte
	copy(fork[:], forkBytes)
	switch fork {
	case [4]byte{0x00, 0x00, 0x10, 0x20}:
		return fork, "prater", nil
	case [4]byte{0, 0, 0, 0}:
		return fork, "mainnet", nil
	case [4]byte{0x99, 0x99, 0x99, 0x99}:
		return fork, "now_test_network", nil
	default:
		return [4]byte{0, 0, 0, 0}, "mainnet", nil
	}
}

// OperatorPrivateKeyFlag  adds private key flag to the command
func InitiatorPrivateKeyFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, initiatorPrivKey, "", "Path to initiator Private Key file", false)
}

// GetOperatorPrivateKeyFlagValue gets private key flag from the command
func GetInitiatorPrivateKeyFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(initiatorPrivKey)
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

// DBPathFlag adds path for storage flag to the command
func DBPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, DBPath, "./data/db", "Path for storage", false)
}

// GetDBPathFlagValue gets path for storage flag from the command
func GetDBPathFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(DBPath)
}

// DBReportingFlag adds flag to run on-off db size reporting to the command
func DBReportingFlag(c *cobra.Command) {
	AddPersistentBoolFlag(c, DBReporting, false, "Flag to run on-off db size reporting", false)
}

// GetDBReportingFlagValue gets flag flag to run on-off db size reporting
func GetDBReportingFlagValue(c *cobra.Command) (bool, error) {
	return c.Flags().GetBool(DBReporting)
}

// DBGCIntervalFlag adds path for storage flag to the command
func DBGCIntervalFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, DBGCInterval, "6m", "Interval between garbage collection cycles. Set to 0 to disable.", false)
}

// GetDBGCIntervalFlagValue gets path for storage flag from the command
func GetDBGCIntervalFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(DBGCInterval)
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

// AddNetworkFlag adds the network key flag to the command
func AddNetworkFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, networkFlag, "now_test_network", "network", false)
}

// GetNetworkFlag gets the network key flag from the command
func GetNetworkFlag(c *cobra.Command) (string, error) {
	return c.Flags().GetString(networkFlag)
}

func AddDepositResultStorePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, depositResultsPath, "./", "Path to store deposit result file json", false)
}

func GetDepositResultStorePathFlag(c *cobra.Command) (string, error) {
	return c.Flags().GetString(depositResultsPath)
}

func AddSSVPayloadResultStorePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, ssvPayloadResultsPath, "./", "Path to store ssv contract payload file json", false)
}

func GetSSVPayloadResultStorePathFlag(c *cobra.Command) (string, error) {
	return c.Flags().GetString(ssvPayloadResultsPath)
}

func AddStoreShareFlag(c *cobra.Command) {
	AddPersistentBoolFlag(c, storeShare, false, "Store BLS share as json", false)
}

func GetStoreShareFlag(c *cobra.Command) (bool, error) {
	return c.Flags().GetBool(storeShare)
}
