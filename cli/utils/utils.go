package utils

import (
	"crypto/rsa"
	"encoding/base64"
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

func OpenPrivateKey(passwordFilePath, privKeyPath string, logger *zap.Logger) *rsa.PrivateKey {
	var privateKey *rsa.PrivateKey
	var err error
	logger.Info("🔑 opening initiator RSA private key file")
	if passwordFilePath != "" {
		logger.Info("🔑 path to password file is provided - decrypting")
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
			logger.Fatal("😥 Password file doesn`t exist: ", zap.Error(err))
		}
		encryptedRSAJSON, err := os.ReadFile(privKeyPath)
		if err != nil {
			logger.Fatal("😥 Cant read operator`s key file", zap.Error(err))
		}
		keyStorePassword, err := os.ReadFile(passwordFilePath)
		if err != nil {
			logger.Fatal("😥 Error reading password file: ", zap.Error(err))
		}
		privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, string(keyStorePassword))
		if err != nil {
			logger.Fatal(err.Error())
		}
	} else {
		logger.Info("🔑 password for key NOT provided - trying to read plaintext key")
		privateKey, err = crypto.PrivateKey(privKeyPath)
		if err != nil {
			logger.Fatal("😥 Error reading plaintext private key from file: ", zap.Error(err))
		}
	}
	return privateKey
}

func GenerateRSAKeyPair(passwordFilePath, privKeyPath string, logger *zap.Logger) (*rsa.PrivateKey, []byte) {
	var privateKey *rsa.PrivateKey
	var err error
	var password string
	logger.Info("🔑 generating new initiator RSA key pair + password")
	pk, priv, err := rsaencryption.GenerateKeys()
	if err != nil {
		logger.Fatal("Failed to generate operator keys", zap.Error(err))
	}
	if passwordFilePath != "" {
		logger.Info("🔑 path to password file is provided")
		// check if a password string a valid path, then read password from the file
		if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
			logger.Fatal("😥 Password file doesn`t exist: ", zap.Error(err))
		}
		keyStorePassword, err := os.ReadFile(passwordFilePath)
		if err != nil {
			logger.Fatal("😥 Error reading password file: ", zap.Error(err))
		}
		password = string(keyStorePassword)
	} else {
		password, err = crypto.GenerateSecurePassword()
		if err != nil {
			logger.Fatal("Failed to generate operator keys", zap.Error(err))
		}
	}
	logger.Info("Generated public key (base64)", zap.String("pk", base64.StdEncoding.EncodeToString(pk)))
	encryptedData, err := keystorev4.New().Encrypt(priv, password)
	if err != nil {
		logger.Fatal("Failed to encrypt private key", zap.Error(err))
	}
	encryptedRSAJSON, err := json.Marshal(encryptedData)
	if err != nil {
		logger.Fatal("Failed to marshal encrypted data to JSON", zap.Error(err))
	}
	privateKey, err = crypto.ConvertEncryptedPemToPrivateKey(encryptedRSAJSON, password)
	if err != nil {
		logger.Fatal(err.Error())
	}
	return privateKey, encryptedRSAJSON
}
func ReadOperatorsInfoFile(operatorsInfoPath string, logger *zap.Logger) initiator.Operators {
	var opMap initiator.Operators
	logger.Info("📖 looking operators info 'operators_info.json' file", zap.String("at path", operatorsInfoPath))
	stat, err := os.Stat(operatorsInfoPath)
	if os.IsNotExist(err) {
		logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
	}
	if stat.IsDir() {
		filePath := operatorsInfoPath + "operators_info.json"
		if _, err := os.Stat(filePath); os.IsNotExist(err) {
			logger.Fatal("😥 Failed to find operator info file at provided path: ", zap.Error(err))
		}
		opsfile, err := os.ReadFile(filePath)
		if err != nil {
			logger.Fatal("😥 Failed to read operator info file:", zap.Error(err))
		}
		opMap, err = initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
	} else {
		logger.Info("📖 reading operators info JSON file")
		opsfile, err := os.ReadFile(operatorsInfoPath)
		if err != nil {
			logger.Fatal("😥 Failed to read operator info file: ", zap.Error(err))
		}
		opMap, err = initiator.LoadOperatorsJson(opsfile)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
	}
	return opMap
}
