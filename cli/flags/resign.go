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

func SetBaseResignMsgFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	OperatorsInfoFlag(cmd)
	OperatorsInfoPathFlag(cmd)
	OperatorIDsFlag(cmd)
	OwnerAddressFlag(cmd)
	NonceFlag(cmd)
	AmountFlag(cmd)
	NetworkFlag(cmd)
	WithdrawAddressFlag(cmd)
	SetProofsFilePath(cmd)
	ProofsStringFlag(cmd)
}

func SetGenerateResignMsgFlags(cmd *cobra.Command) {
	SetBaseResignMsgFlags(cmd)
}

func SetResigningFlags(cmd *cobra.Command) {
	SetGenerateResignMsgFlags(cmd)
	ClientCACertPathFlag(cmd)
	SetTLSInsecureFlag(cmd)
	SignaturesFlag(cmd)
}

func BindGenerateResignMsgFlags(cmd *cobra.Command) error {
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
	if err := viper.BindPFlag("amount", cmd.PersistentFlags().Lookup("amount")); err != nil {
		return err
	}
	if err := viper.BindPFlag("proofsFilePath", cmd.PersistentFlags().Lookup("proofsFilePath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("proofsString", cmd.PersistentFlags().Lookup("proofsString")); err != nil {
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
	OperatorIDs = viper.GetStringSlice("operatorIDs")
	if len(OperatorIDs) == 0 {
		return fmt.Errorf("😥 operator IDs flag cant be empty")
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
		return fmt.Errorf("😥 wrong operatorsInfoPath flag")
	}
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 failed to get owner address flag value")
	}
	Nonce = viper.GetUint64("nonce")
	Amount = viper.GetUint64("amount")
	if !spec.ValidAmountSet(phase0.Gwei(Amount)) {
		return fmt.Errorf("🚨 amount should be in range between 32 ETH and 2048 ETH")
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
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 failed to parse owner address: %s", err)
	}
	return nil
}

// BindResigningFlags binds flags to yaml config parameters for the resigning of previous DKG result
func BindResigningFlags(cmd *cobra.Command) error {
	if err := BindGenerateResignMsgFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("signatures", cmd.PersistentFlags().Lookup("signatures")); err != nil {
		return err
	}
	Signatures = viper.GetString("signatures")
	if Signatures == "" {
		return fmt.Errorf("😥 Failed to get --signatures flag value")
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
		if len(ClientCACertPath) == 0 {
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
