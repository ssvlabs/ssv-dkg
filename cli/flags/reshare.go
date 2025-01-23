package flags

import (
	"fmt"
	"path/filepath"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
)

// Flag names.
const (
	newOperatorIDs = "newOperatorIDs"
	proofsFilePath = "proofsFilePath"
	proofsString   = "proofsString"
	signatures     = "signatures"
)

// resigning/reshare flags
var (
	ProofsFilePath string
	ProofsString   string
	NewOperatorIDs []string
	Signatures     string
)

func SetBaseReshareFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	OperatorsInfoFlag(cmd)
	OperatorsInfoPathFlag(cmd)
	OperatorIDsFlag(cmd)
	NewOperatorIDsFlag(cmd)
	WithdrawAddressFlag(cmd)
	OwnerAddressFlag(cmd)
	NonceFlag(cmd)
	AmountFlag(cmd)
	NetworkFlag(cmd)
	SetProofsFilePath(cmd)
	ProofsStringFlag(cmd)
}

func SetGenerateReshareMsgFlags(cmd *cobra.Command) {
	SetBaseReshareFlags(cmd)
}

func SetReshareFlags(cmd *cobra.Command) {
	SetBaseReshareFlags(cmd)
	ClientCACertPathFlag(cmd)
	SetTLSInsecureFlag(cmd)
	SignaturesFlag(cmd)
}

func BindGenerateReshareMsgFlags(cmd *cobra.Command) error {
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
	if err := viper.BindPFlag("amount", cmd.PersistentFlags().Lookup("amount")); err != nil {
		return err
	}
	if err := viper.BindPFlag("proofsFilePath", cmd.PersistentFlags().Lookup("proofsFilePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("proofsString", cmd.PersistentFlags().Lookup("proofsString")); err != nil {
		return err
	}
	OperatorsInfoPath = viper.GetString("operatorsInfoPath")
	if OperatorsInfoPath != "" {
		OperatorsInfoPath = filepath.Clean(OperatorsInfoPath)
	}
	OperatorsInfo = viper.GetString("operatorsInfo")
	if OperatorsInfoPath != "" && OperatorsInfo != "" {
		return fmt.Errorf("😥 operators info can be provided either as a raw JSON string, or path to a file, not both")
	}
	if OperatorsInfoPath == "" && OperatorsInfo == "" {
		return fmt.Errorf("😥 operators info should be provided either as a raw JSON string, or path to a file")
	}
	if OperatorsInfoPath != "" && !filepath.IsLocal(OperatorsInfoPath) {
		return fmt.Errorf("😥 wrong operatorsInfoPath flag, should be local")
	}
	OperatorIDs = viper.GetStringSlice("operatorIDs")
	if len(OperatorIDs) == 0 {
		return fmt.Errorf("😥 old operator IDs flag cannot be empty")
	}
	NewOperatorIDs = viper.GetStringSlice("newOperatorIDs")
	if len(NewOperatorIDs) == 0 {
		return fmt.Errorf("😥 new operator IDs flag cannot be empty")
	}
	ProofsFilePath = viper.GetString("proofsFilePath")
	if ProofsFilePath != "" {
		ProofsFilePath = filepath.Clean(ProofsFilePath)
	}
	ProofsString = viper.GetString("proofsString")
	if ProofsFilePath == "" && ProofsString == "" {
		return fmt.Errorf("😥 failed to get proofs from proofs string or path to proofs flag value")
	}
	if ProofsFilePath != "" && ProofsString != "" {
		return fmt.Errorf("😥 proofs can be provided either as a string, or path to a file, not both")
	}
	if ProofsFilePath != "" && !filepath.IsLocal(ProofsFilePath) {
		return fmt.Errorf("😥 wrong proofsFilePath flag, should be local")
	}
	withdrawAddr := viper.GetString("withdrawAddress")
	if withdrawAddr == "" {
		return fmt.Errorf("😥 failed to get withdrawal address flag value")
	}
	var err error
	WithdrawAddress, err = utils.HexToAddress(withdrawAddr)
	if err != nil {
		return fmt.Errorf("😥 failed to parse withdraw address: %s", err.Error())
	}
	Network = viper.GetString("network")
	if Network == "" {
		return fmt.Errorf("😥 failed to get fork version flag value")
	}
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 failed to get owner address flag value")
	}
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 failed to parse owner address: %s", err)
	}
	Nonce = viper.GetUint64("nonce")
	Amount = viper.GetUint64("amount")
	if !spec.ValidAmountSet(phase0.Gwei(Amount)) {
		return fmt.Errorf("🚨 Amount should be in range between 32 ETH and 2048 ETH")
	}
	return nil
}

// BindReshareFlags binds flags to yaml config parameters for the resharing ceremony of DKG
func BindReshareFlags(cmd *cobra.Command) error {
	if err := BindGenerateReshareMsgFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("signatures", cmd.PersistentFlags().Lookup("signatures")); err != nil {
		return err
	}
	Signatures = viper.GetString("signatures")
	if Signatures == "" {
		return fmt.Errorf("😥 failed to get --signatures flag value")
	}
	if err := viper.BindPFlag("clientCACertPath", cmd.PersistentFlags().Lookup("clientCACertPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("tlsInsecure", cmd.PersistentFlags().Lookup("tlsInsecure")); err != nil {
		return err
	}
	TLSInsecure = viper.GetBool("tlsInsecure")
	if !TLSInsecure {
		ClientCACertPath = viper.GetStringSlice("clientCACertPath")
		if ClientCACertPath == nil {
			return fmt.Errorf("😥 TLS CA certs path should be provided, overwise set 'TLSInsecure' flag to true")
		} else {
			for _, certPath := range ClientCACertPath {
				if !filepath.IsLocal(certPath) {
					return fmt.Errorf("😥 wrong clientCACertPath flag, should be local")
				}
			}
		}
	} else {
		ClientCACertPath = []string{}
	}
	return nil
}

// newOperatorIDsFlag adds new operators IDs flag to the command
func NewOperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, newOperatorIDs, []string{}, "New operator IDs for resharing ceremony", false)
}

// ProofsFilePath add file path to proofs flag to the command
func SetProofsFilePath(c *cobra.Command) {
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
