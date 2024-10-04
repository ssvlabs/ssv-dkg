package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Flag names.
const (
	withdrawAddress   = "withdrawAddress"
	operatorIDs       = "operatorIDs"
	newOperatorIDs    = "newOperatorIDs"
	operatorsInfo     = "operatorsInfo"
	operatorsInfoPath = "operatorsInfoPath"
	privKey           = "privKey"
	privKeyPassword   = "privKeyPassword"
	configPath        = "configPath"
	operatorPort      = "port"
	owner             = "owner"
	nonce             = "nonce"
	network           = "network"
	outputPath        = "outputPath"
	logLevel          = "logLevel"
	logFormat         = "logFormat"
	logLevelFormat    = "logLevelFormat"
	logFilePath       = "logFilePath"
	validators        = "validators"
	operatorID        = "operatorID"
	clientCACertPath  = "clientCACertPath"
	serverTLSCertPath = "serverTLSCertPath"
	serverTLSKeyPath  = "serverTLSKeyPath"
	proofsFilePath    = "proofsFilePath"
	proofsString      = "proofsString"
	ethEndpointURL    = "ethEndpointURL"
	signatures        = "signatures"
)

// WithdrawAddressFlag  adds withdraw address flag to the command
func WithdrawAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, withdrawAddress, "", "Withdrawal address", false)
}

// operatorIDsFlag adds operators IDs flag to the command
func OperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, operatorIDs, []string{"1", "2", "3"}, "Operator IDs", false)
}

// newOperatorIDsFlag adds new operators IDs flag to the command
func NewOperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, newOperatorIDs, []string{"1", "2", "3"}, "New operator IDs for resharing ceremony", false)
}

// OperatorsInfoFlag  adds path to operators' ifo file flag to the command
func OperatorsInfoFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorsInfo, "", "Raw JSON string operators' public keys, IDs and IPs file e.g. `'[{\"id\":1,\"public_key\":\"xxx\",\"ip\":\"10.0.0.1:3033\"},...]'`", false)
}

// OperatorsInfoFlag  adds path to operators' ifo file flag to the command
func OperatorsInfoPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorsInfoPath, "", "Path to a file containing operators' public keys, IDs and IPs file e.g. [{\"id\":1,\"public_key\":\"xxx\",\"ip\":\"10.0.0.1:3033\"},...]", false)
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

// OperatorPrivateKeyPassFlag  adds private key flag to the command
func PrivateKeyPassFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, privKeyPassword, "", "Password to decrypt initiator`s Private Key file", false)
}

// OperatorPortFlag  adds operator listening port flag to the command
func OperatorPortFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, operatorPort, 3030, "Operator Private Key hex", false)
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

// ResultPathFlag sets the path to store resulting files
func ResultPathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, outputPath, "./output", "Path to store results", false)
}

// ClientCACertPathFlag sets path to client CA certificates
func ClientCACertPathFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, clientCACertPath, []string{}, "Path to client CA certificates", false)
}

// ServerTLSCertPath sets path to server TLS certificate
func ServerTLSCertPath(c *cobra.Command) {
	AddPersistentStringFlag(c, serverTLSCertPath, "/ssl/tls.crt", "Path to server TLS certificate", false)
}

// ServerTLSKeyPath sets path to server server TLS private key
func ServerTLSKeyPath(c *cobra.Command) {
	AddPersistentStringFlag(c, serverTLSKeyPath, "/ssl/tls.key", "Path to server TLS private key", false)
}

// ValidatorsFlag add number of validators to create flag to the command
func ValidatorsFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, validators, 1, "Number of validators", false)
}

// OperatorIDFlag add operator ID flag to the command
func OperatorIDFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, operatorID, 0, "Operator ID", false)
}

// ProofsFilePath add file path to proofs flag to the command
func ProofsFilePath(c *cobra.Command) {
	AddPersistentStringFlag(c, proofsFilePath, "", "Path to proofs file, provide this OR a stringified proofs", false)
}

// ProofsStringFlag add proofs string flag to the command
func ProofsStringFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, proofsString, "", "Stringified proofs, provide this OR a path to proofs file", false)
}

// SignaturesFlag add signatures flag to the command
func SignaturesFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, signatures, "", "Stringified signature(s) for the resign/reshare message", false)
}

// EthEndpointURL
func EthEndpointURL(c *cobra.Command) {
	AddPersistentStringFlag(c, ethEndpointURL, "http://127.0.0.1:8545", "Ethereum node endpoint URL", false)
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
