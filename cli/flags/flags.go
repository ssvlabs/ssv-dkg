package flags

import (
	"fmt"

	"github.com/spf13/cobra"
)

// Flag names.
const (
	threshold       = "threshold"
	withdrawAddress = "withdrawAddress"
	operatorIDs     = "operatorIDs"
	operatorsInfo   = "operatorsInfoPath"
	operatorPrivKey = "privKey"
	operatorPort    = "port"
)

// ThresholdFlag adds threshold flag to the command
func ThresholdFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, threshold, 3, "Threshold for distributed signature", true)
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
	AddPersistentStringSliceFlag(c, operatorIDs, []string{"1", "2", "3"}, "Operator IDs", true)
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

// OperatorPrivateKeyFlag  adds private key flag to the command
func OperatorPrivateKeyFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, operatorPrivKey, "", "Path to operator Private Key file", false)
}

// GetOperatorPrivateKeyFlagValue gets private key flag from the command
func GetOperatorPrivateKeyFlagValue(c *cobra.Command) (string, error) {
	return c.Flags().GetString(operatorPrivKey)
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
