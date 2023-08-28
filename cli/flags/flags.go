package flags

import (
	"encoding/hex"
	"fmt"

	"github.com/spf13/cobra"
)

// Flag names.
const (
	threshold             = "threshold"
	withdrawAddress       = "withdrawAddress"
	operatorIDs           = "operatorIDs"
	operatorsInfo         = "operatorsInfoPath"
	operatorPrivKey       = "privKey"
	operatorPort          = "port"
	owner                 = "owner"
	nonce                 = "nonce"
	fork                  = "fork"
	mnemonicFlag          = "mnemonic"
	indexFlag             = "index"
	networkFlag           = "network"
	password              = "password"
	depositResultsPath    = "depositResultsPath"
	ssvPayloadResultsPath = "ssvPayloadResultsPath"
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
func OperatorPrivateKeyFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorPrivKey, "", "Path to operator Private Key file", false)
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

// GetOperatorPortFlagValue gets operator listening port flag from the command
func GetOperatorPortFlagValue(c *cobra.Command) (uint64, error) {
	return c.Flags().GetUint64(operatorPort)
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
	AddPersistentStringFlag(c, depositResultsPath, "", "Path to store deposit result file json", false)
}

func GetDepositResultStorePathFlag(c *cobra.Command) (string, error) {
	return c.Flags().GetString(depositResultsPath)
}

func AddSSVPayloadResultStorePathFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, ssvPayloadResultsPath, "", "Path to store ssv contract payload file json", false)
}

func GetSSVPayloadResultStorePathFlag(c *cobra.Command) (string, error) {
	return c.Flags().GetString(ssvPayloadResultsPath)
}
