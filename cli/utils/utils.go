package utils

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"os"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/spf13/cobra"
	"github.com/spf13/viper"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/cli/flags"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
)

func SetViperConfig(cmd *cobra.Command) error {
	viper.SetConfigType("yaml")
	configPath, err := flags.GetConfigPathFlagValue(cmd)
	if err != nil {
		return err
	}
	if configPath != "" {
		viper.SetConfigFile(configPath)
	}
	if err := viper.ReadInConfig(); err != nil {
		if _, ok := err.(viper.ConfigFileNotFoundError); !ok {
			return err
		}
		fmt.Print("⚠️ config file was not provided, using flag parameters \n")
	}
	return nil
}

func SetGlobalLogger(cmd *cobra.Command, name string) (*zap.Logger, error) {
	// workaround for https://github.com/spf13/viper/issues/233
	if err := viper.BindPFlag("logLevel", cmd.Flags().Lookup("logLevel")); err != nil {
		return nil, err
	}
	if err := viper.BindPFlag("logFormat", cmd.Flags().Lookup("logFormat")); err != nil {
		return nil, err
	}
	if err := viper.BindPFlag("logLevelFormat", cmd.Flags().Lookup("logLevelFormat")); err != nil {
		return nil, err
	}
	if err := viper.BindPFlag("logFilePath", cmd.Flags().Lookup("logFilePath")); err != nil {
		return nil, err
	}
	logLevel := viper.GetString("logLevel")
	logFormat := viper.GetString("logFormat")
	logLevelFormat := viper.GetString("logLevelFormat")
	logFilePath := viper.GetString("logFilePath")
	if logFilePath == "" {
		fmt.Print("⚠️ debug log path was not provided, using default: ./initiator_debug.log \n")
	}
	// If the log file doesn't exist, create it
	_, err := os.OpenFile(logFilePath, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0644)
	if err != nil {
		return nil, err
	}
	if err := logging.SetGlobalLogger(logLevel, logFormat, logLevelFormat, &logging.LogFileOptions{FileName: logFilePath}); err != nil {
		return nil, fmt.Errorf("logging.SetGlobalLogger: %w", err)
	}
	logger := zap.L().Named(name)
	return logger, nil
}

func OpenPrivateKey(passwordFilePath, privKeyPath string) (*rsa.PrivateKey, error) {
	var privateKey *rsa.PrivateKey
	var err error
	if passwordFilePath != "" {
		fmt.Println("🔑 path to password file is provided - decrypting")
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("😥 Password file doesn`t exist: %s", err)
		}
		encryptedRSAJSON, err := os.ReadFile(privKeyPath)
		if err != nil {
			return nil, fmt.Errorf("😥 Cant read operator`s key file: %s", err)
		}
		keyStorePassword, err := os.ReadFile(passwordFilePath)
		if err != nil {
			return nil, fmt.Errorf("😥 Error reading password file: %s", err)
		}
		privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, string(keyStorePassword))
		if err != nil {
			return nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
		}
	} else {
		fmt.Println("🔑 password for key NOT provided - trying to read plaintext key")
		privateKey, err = crypto.PrivateKey(privKeyPath)
		if err != nil {
			return nil, fmt.Errorf("😥 Error reading plaintext private key from file: %s", err)
		}
	}
	return privateKey, nil
}

func GenerateRSAKeyPair(passwordFilePath, privKeyPath string) (*rsa.PrivateKey, []byte, error) {
	var privateKey *rsa.PrivateKey
	var err error
	var password string
	_, priv, err := rsaencryption.GenerateKeys()
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Failed to generate operator keys: %s", err)
	}
	if passwordFilePath != "" {
		fmt.Println("🔑 path to password file is provided")
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
			return nil, nil, fmt.Errorf("😥 Password file doesn`t exist: %s", err)
		}
		keyStorePassword, err := os.ReadFile(passwordFilePath)
		if err != nil {
			return nil, nil, fmt.Errorf("😥 Error reading password file: %s", err)
		}
		password = string(keyStorePassword)
	} else {
		password, err = crypto.GenerateSecurePassword()
		if err != nil {
			return nil, nil, fmt.Errorf("😥 Failed to generate operator keys: %s", err)
		}
	}
	encryptedData, err := keystorev4.New().Encrypt(priv, password)
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Failed to encrypt private key: %s", err)
	}
	encryptedRSAJSON, err := json.Marshal(encryptedData)
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Failed to marshal encrypted data to JSON: %s", err)
	}
	privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, password)
	if err != nil {
		return nil, nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
	}
	return privateKey, encryptedRSAJSON, nil
}
func ReadOperatorsInfoFile(operatorsInfoPath string) (initiator.Operators, error) {
	var opMap initiator.Operators
	fmt.Printf("📖 looking operators info 'operators_info.json' file: %s \n", operatorsInfoPath)
	stat, err := os.Stat(operatorsInfoPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
	}
	if stat.IsDir() {
		filePath := operatorsInfoPath + "operators_info.json"
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			return nil, fmt.Errorf("😥 Failed to find operator info file at provided path: %s", err)
		}
		opsfile, err := os.ReadFile(filePath)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
		}
		opMap, err = initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to load operators: %s", err)
		}
	} else {
		fmt.Println("📖 reading operators info JSON file")
		opsfile, err := os.ReadFile(operatorsInfoPath)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
		}
		opMap, err = initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			return nil, fmt.Errorf("😥 Failed to load operators: %s", err)
		}
	}
	return opMap, nil
}
