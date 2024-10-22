package flags

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
)

// verify flags
var (
	CeremonyDir string
)

func SetVerifyFlags(cmd *cobra.Command) {
	AddPersistentStringFlag(cmd, "ceremonyDir", "", "Path to the ceremony directory", true)
	ValidatorsFlag(cmd)
	WithdrawAddressFlag(cmd)
	OwnerAddressFlag(cmd)
	NonceFlag(cmd)
	AmountFlag(cmd)
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
	if err := viper.BindPFlag("amount", cmd.PersistentFlags().Lookup("amount")); err != nil {
		return err
	}
	if err := viper.BindPFlag("owner", cmd.PersistentFlags().Lookup("owner")); err != nil {
		return err
	}
	CeremonyDir = filepath.Clean(viper.GetString("ceremonyDir"))
	if strings.Contains(CeremonyDir, "..") {
		return fmt.Errorf("😥 wrong CeremonyDir flag")
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
	Amount = viper.GetUint64("amount")
	if !spec.ValidAmountSet(phase0.Gwei(Amount)) {
		return fmt.Errorf("🚨 Amount should be in range between 32 ETH and 2048 ETH")
	}
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
