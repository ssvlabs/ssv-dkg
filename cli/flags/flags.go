package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Flag names.
const (
	threshold                         = "threshold"
	withdrawAddress                   = "withdrawAddress"
	operatorIDs                       = "operatorIDs"
	newOperatorIDs                    = "newOperatorIDs"
	operatorsInfo                     = "operatorsInfo"
	operatorsInfoPath                 = "operatorsInfoPath"
	privKey                           = "privKey"
	privKeyPassword                   = "privKeyPassword"
	configPath                        = "configPath"
	generateInitiatorKeyIfNotExisting = "generateInitiatorKeyIfNotExisting"
	operatorPort                      = "port"
	owner                             = "owner"
	nonce                             = "nonce"
	network                           = "network"
	outputPath                        = "outputPath"
	logLevel                          = "logLevel"
	logFormat                         = "logFormat"
	logLevelFormat                    = "logLevelFormat"
	logFilePath                       = "logFilePath"
	validators                        = "validators"
	operatorID                        = "operatorID"
	keysharesFilePath                 = "keysharesFilePath"
	ceremonySigsFilePath              = "ceremonySigsFilePath"
	beaconNodeAddress                 = "beaconNodeAddress"
)

// ThresholdFlag adds threshold flag to the command
func ThresholdFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, threshold, 0, "Threshold for distributed signature", false)
}

// WithdrawAddressFlag  adds withdraw address flag to the command
func WithdrawAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, withdrawAddress, "", "Withdrawal address", false)
}

// operatorIDsFlag adds operators IDs flag to the command
func OperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, operatorIDs, []string{"1", "2", "3"}, "Operator IDs", false)
}

// operatorIDsFlag adds new operators IDs flag to the command
func NewOperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, newOperatorIDs, []string{"1", "2", "3"}, "New operator IDs", false)
}

// OperatorsInfoFlag  adds path to operators' ifo file flag to the command
func OperatorsInfoFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorsInfo, "", "Raw JSON string operators' public keys, IDs and IPs file e.g. `{ 1: { publicKey: XXX, id: 1, ip: 10.0.0.1:3033 }`", false)
}

// OperatorsInfoFlag  adds path to operators' ifo file flag to the command
func OperatorsInfoPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorsInfoPath, "", "Path to a file containing operators' public keys, IDs and IPs file e.g. { 1: { publicKey: XXX, id: 1, ip: 10.0.0.1:3033 }", false)
}

// OwnerAddressFlag  adds owner address flag to the command
func OwnerAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, owner, "", "Owner address", false)
}

// NonceFlag  owner nonce flag to the command
func NonceFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, nonce, 0, "Owner nonce", false)
}

// NetworkFlag  adds the fork version of the network flag to the command
func NetworkFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, network, "mainnet", "Network name: mainnet, prater, holesky", false)
}

// OperatorPrivateKeyFlag  adds private key flag to the command
func PrivateKeyFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, privKey, "", "Path to initiator Private Key file", false)
}

// GenerateInitiatorKeyIfNotExistingFlag adds flag to generate a random secure password and initiator RSA key pair encrypted with this password
func GenerateInitiatorKeyIfNotExistingFlag(c *cobra.Command) {
	AddPersistentBoolFlag(c, generateInitiatorKeyIfNotExisting, false, "Generates a random secure password and initiator RSA key pair encrypted with this password", false)
}

// OperatorPrivateKeyPassFlag  adds private key flag to the command
func PrivateKeyPassFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, privKeyPassword, "", "Password to decrypt initiator`s Private Key file", false)
}

// OperatorPortFlag  adds operator listening port flag to the command
func OperatorPortFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, operatorPort, 3030, "Operator listening port", false)
}

// ConfigPathFlag config path flag to the command
func ConfigPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, configPath, "", "Path to config file", false)
}

// LogLevelFlag logger's log level flag to the command
func LogLevelFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logLevel, "debug", "Defines logger's log level", false)
}

// LogFormatFlag logger's  logger's encoding flag to the command
func LogFormatFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logFormat, "json", "Defines logger's encoding, valid values are 'json' (default) and 'console'", false)
}

// LogLevelFormatFlag logger's level format flag to the command
func LogLevelFormatFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logLevelFormat, "capitalColor", "Defines logger's level format, valid values are 'capitalColor' (default), 'capital' or 'lowercase'", false)
}

// LogFilePathFlag file path to write logs into
func LogFilePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, logFilePath, "debug.log", "Defines a file path to write logs into", false)
}

func ResultPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, outputPath, "./output", "Path to store results", false)
}

// ValidatorsFlag add number of validators to create flag to the command
func ValidatorsFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, validators, 1, "Number of validators", false)
}

// OperatorIDFlag add operator ID flag to the command
func OperatorIDFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, operatorID, 0, "Operator ID", false)
}

func KeysharesFilePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, keysharesFilePath, "", "Path to keyshares json file", false)
}

func CeremonySigsFilePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, ceremonySigsFilePath, "", "Path to ceremony signatures json file", false)
}

func BeaconNoodeAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, beaconNodeAddress, "", "Active beacon node address", false)
}

// AddPersistentStringFlag adds a string flag to the command
func AddPersistentStringFlag(c *cobra.Command, flag, value, description string, isRequired bool) {
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
