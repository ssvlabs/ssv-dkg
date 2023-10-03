package initiator

import (
	"encoding/base64"
	"encoding/json"
	"log"
	"os"

	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/spf13/cobra"
	"go.uber.org/zap"
)

func init() {
	GenerateInitiatorKeysCmd.Flags().StringP("password", "p", "", "Password used to encrypt the private key")
}

// GenerateOperatorKeysCmd is the command to generate operator private/public keys
var GenerateInitiatorKeysCmd = &cobra.Command{
	Use:   "generate-keys",
	Short: "generates RSA keys",
	Run: func(cmd *cobra.Command, args []string) {
		if err := logging.SetGlobalLogger("debug", "capital", "console", &logging.LogFileOptions{FileName: "./data/debug.log"}); err != nil {
			log.Fatal(err)
		}
		logger := zap.L().Named(cmd.Short)
		password, err := cmd.Flags().GetString("password")
		if err != nil {
			logger.Fatal("Failed to get password for RSA key", zap.Error(err))
		}
		pk, sk, err := rsaencryption.GenerateKeys()
		if err != nil {
			logger.Fatal("Failed to generate operator keys", zap.Error(err))
		}
		logger.Info("Generated public key (base64)", zap.String("pk", base64.StdEncoding.EncodeToString(pk)))

		if password != "" {
			encryptedData, err := keystorev4.New().Encrypt(sk, password)
			if err != nil {
				logger.Fatal("Failed to encrypt private key", zap.Error(err))
			}

			encryptedJSON, err := json.Marshal(encryptedData)
			if err != nil {
				logger.Fatal("Failed to marshal encrypted data to JSON", zap.Error(err))
			}

			err = os.WriteFile("encrypted_private_key.json", encryptedJSON, 0600)
			if err != nil {
				logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
			}

			logger.Info("Private key encrypted and stored in encrypted_private_key.json")
		} else {
			logger.Info("Generated public key (base64)", zap.String("pk", base64.StdEncoding.EncodeToString(pk)))
			logger.Info("Generated private key (base64)", zap.String("sk", base64.StdEncoding.EncodeToString(sk)))
		}
	},
}
