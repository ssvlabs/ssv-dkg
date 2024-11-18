package flags

import (
	"fmt"
	"path/filepath"

	"github.com/spf13/cobra"
	"github.com/spf13/viper"

	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
)

// Flag names.
const (
	privKey           = "privKey"
	privKeyPassword   = "privKeyPassword"
	operatorPort      = "port"
	operatorID        = "operatorID"
	serverTLSCertPath = "serverTLSCertPath"
	serverTLSKeyPath  = "serverTLSKeyPath"
	ethEndpointURL    = "ethEndpointURL"
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
	if !filepath.IsLocal(PrivKey) {
		return fmt.Errorf("😥 wrong key path flag value, should be local")
	}
	if !filepath.IsLocal(PrivKeyPassword) {
		return fmt.Errorf("😥 wrong password for private key flag value, should be local")
	}
	Port = viper.GetUint64("port")
	if Port == 0 {
		return fmt.Errorf("😥 wrong port provided")
	}
	OperatorID = viper.GetUint64("operatorID")
	if OperatorID == 0 {
		return fmt.Errorf("😥 wrong operator ID provided")
	}
	ServerTLSCertPath = filepath.Clean(viper.GetString("serverTLSCertPath"))
	if !filepath.IsLocal(ServerTLSCertPath) {
		return fmt.Errorf("😥 wrong serverTLSCertPath flag, should be local")
	}
	ServerTLSKeyPath = filepath.Clean(viper.GetString("serverTLSKeyPath"))
	if !filepath.IsLocal(ServerTLSKeyPath) {
		return fmt.Errorf("😥 wrong serverTLSKeyPath flag, should be local")
	}
	EthEndpointURL = viper.GetString("ethEndpointURL")
	if !cli_utils.IsUrl(EthEndpointURL) {
		return fmt.Errorf("ethereum endpoint URL: %s - Invalid", EthEndpointURL)
	}
	return nil
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

// OperatorIDFlag add operator ID flag to the command
func OperatorIDFlag(c *cobra.Command) {
	AddPersistentIntFlag(c, operatorID, 0, "Operator ID", false)
}

// ServerTLSCertPath sets path to server TLS certificate
func SetServerTLSCertPath(c *cobra.Command) {
	AddPersistentStringFlag(c, serverTLSCertPath, "./ssl/tls.crt", "Path to server TLS certificate", false)
}

// ServerTLSKeyPath sets path to server server TLS private key
func SetServerTLSKeyPath(c *cobra.Command) {
	AddPersistentStringFlag(c, serverTLSKeyPath, "./ssl/tls.key", "Path to server TLS private key", false)
}

// SetEthEndpointURL
func SetEthEndpointURL(c *cobra.Command) {
	AddPersistentStringFlag(c, ethEndpointURL, "http://127.0.0.1:8545", "Ethereum node endpoint URL", false)
}
