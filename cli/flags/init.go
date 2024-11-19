package flags

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
)

// Flag names.
const (
	withdrawAddress   = "withdrawAddress"
	operatorIDs       = "operatorIDs"
	operatorsInfo     = "operatorsInfo"
	operatorsInfoPath = "operatorsInfoPath"
	owner             = "owner"
	nonce             = "nonce"
	amount            = "amount"
	network           = "network"
	validators        = "validators"
	clientCACertPath  = "clientCACertPath"
	tlsInsecure       = "tlsInsecure"
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
	Amount            uint64
	Validators        uint
	ClientCACertPath  []string
	TLSInsecure       bool
)

func SetInitFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	OperatorsInfoFlag(cmd)
	OperatorsInfoPathFlag(cmd)
	OperatorIDsFlag(cmd)
	OwnerAddressFlag(cmd)
	NonceFlag(cmd)
	AmountFlag(cmd)
	NetworkFlag(cmd)
	WithdrawAddressFlag(cmd)
	ValidatorsFlag(cmd)
	ClientCACertPathFlag(cmd)
	SetTLSInsecureFlag(cmd)
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
	if err := viper.BindPFlag("amount", cmd.PersistentFlags().Lookup("amount")); err != nil {
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
	owner := viper.GetString("owner")
	if owner == "" {
		return fmt.Errorf("😥 Failed to get owner address flag value")
	}
	Amount = viper.GetUint64("amount")
	if !spec.ValidAmountSet(phase0.Gwei(Amount)) {
		return fmt.Errorf("🚨 Amount should be in range between 32 ETH and 2048 ETH")
	}
	OwnerAddress, err = utils.HexToAddress(owner)
	if err != nil {
		return fmt.Errorf("😥 Failed to parse owner address: %s", err)
	}
	Nonce = viper.GetUint64("nonce")
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

// SetViperConfig reads a yaml config file if provided
func SetViperConfig(cmd *cobra.Command) error {
	if err := viper.BindPFlag("configPath", cmd.PersistentFlags().Lookup("configPath")); err != nil {
		return err
	}
	ConfigPath = viper.GetString("configPath")
	if ConfigPath != "" && filepath.Clean(ConfigPath) != "" {
		if !filepath.IsLocal(ConfigPath) {
			return fmt.Errorf("😥 wrong configPath flag, should be local")
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

// WithdrawAddressFlag  adds withdraw address flag to the command
func WithdrawAddressFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, withdrawAddress, "", "Withdrawal address", false)
}

// operatorIDsFlag adds operators IDs flag to the command
func OperatorIDsFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, operatorIDs, []string{"1", "2", "3"}, "Operator IDs", false)
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

// NonceFlag adds nonce flag to the command
func NonceFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, nonce, 0, "Owner nonce", false)
}

// AmountFlag adds amount in Gwei flag to the command (https://eips.ethereum.org/EIPS/eip-7251)
func AmountFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, amount, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), "Amount in Gwei", false)
}

// NetworkFlag  adds the fork version of the network flag to the command
func NetworkFlag(c *cobra.Command) {
	AddPersistentStringFlag(c, network, "mainnet", "Network name: mainnet, prater, holesky", false)
}

// ClientCACertPathFlag sets path to client CA certificates. For Ubuntu use `sudo apt install ca-certificates`
func ClientCACertPathFlag(c *cobra.Command) {
	AddPersistentStringSliceFlag(c, clientCACertPath, []string{"/etc/ssl/certs/ca-certificates.crt"}, "Path to client CA certificates", false)
}

// ValidatorsFlag add number of validators to create flag to the command
func ValidatorsFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, validators, 1, "Number of validators", false)
}

// SetTLSInsecureFlag add signatures flag to the command
func SetTLSInsecureFlag(c *cobra.Command) {
	AddPersistentBoolFlag(c, tlsInsecure, false, "TLS 'InsecureSkipVerify' option. If true, allow any TLS certs to accept", false)
}
