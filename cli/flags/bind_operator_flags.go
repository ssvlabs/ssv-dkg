package flags

import (
	"fmt"
	"path/filepath"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
)

// operator flags
var (
	PrivKey           string
	PrivKeyPassword   string
	Port              uint64
	OperatorID        uint64
	ServerTLSCertPath string
	ServerTLSKeyPath  string
	EthEndpointURL    string
)

func SetOperatorFlags(cmd *cobra.Command) {
	SetBaseFlags(cmd)
	PrivateKeyFlag(cmd)
	PrivateKeyPassFlag(cmd)
	OperatorPortFlag(cmd)
	OperatorIDFlag(cmd)
	SetServerTLSCertPath(cmd)
	SetServerTLSKeyPath(cmd)
	SetEthEndpointURL(cmd)
}

// BindOperatorFlags binds flags to yaml config parameters for the operator
func BindOperatorFlags(cmd *cobra.Command) error {
	if err := BindBaseFlags(cmd); err != nil {
		return err
	}
	if err := viper.BindPFlag("privKey", cmd.PersistentFlags().Lookup("privKey")); err != nil {
		return err
	}
	if err := viper.BindPFlag("privKeyPassword", cmd.PersistentFlags().Lookup("privKeyPassword")); err != nil {
		return err
	}
	if err := viper.BindPFlag("port", cmd.PersistentFlags().Lookup("port")); err != nil {
		return err
	}
	if err := viper.BindPFlag("operatorID", cmd.PersistentFlags().Lookup("operatorID")); err != nil {
		return err
	}
	if err := viper.BindPFlag("serverTLSCertPath", cmd.PersistentFlags().Lookup("serverTLSCertPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("serverTLSKeyPath", cmd.PersistentFlags().Lookup("serverTLSKeyPath")); err != nil {
		return err
	}
	if err := viper.BindPFlag("ethEndpointURL", cmd.PersistentFlags().Lookup("ethEndpointURL")); err != nil {
		return err
	}
	PrivKey = filepath.Clean(viper.GetString("privKey"))
	PrivKeyPassword = filepath.Clean(viper.GetString("privKeyPassword"))
	if strings.Contains(PrivKey, "..") {
		return fmt.Errorf("😥 Failed to get private key path flag value")
	}
	if strings.Contains(PrivKeyPassword, "..") {
		return fmt.Errorf("😥 Failed to get password for private key flag value")
	}
	Port = viper.GetUint64("port")
	if Port == 0 {
		return fmt.Errorf("😥 Wrong port provided")
	}
	OperatorID = viper.GetUint64("operatorID")
	if OperatorID == 0 {
		return fmt.Errorf("😥 Wrong operator ID provided")
	}
	ServerTLSCertPath = filepath.Clean(viper.GetString("serverTLSCertPath"))
	if strings.Contains(ServerTLSCertPath, "..") {
		return fmt.Errorf("😥 wrong serverTLSCertPath flag")
	}
	ServerTLSKeyPath = filepath.Clean(viper.GetString("serverTLSKeyPath"))
	if strings.Contains(ServerTLSKeyPath, "..") {
		return fmt.Errorf("😥 wrong serverTLSKeyPath flag")
	}
	EthEndpointURL = viper.GetString("ethEndpointURL")
	if !cli_utils.IsUrl(EthEndpointURL) {
		return fmt.Errorf("ethereum endpoint URL: %s - Invalid", EthEndpointURL)
	}
	return nil
}
