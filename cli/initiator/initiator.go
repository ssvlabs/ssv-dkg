package initiator

import (
	"encoding/hex"
	"fmt"
	"os"

	"github.com/spf13/cobra"
	"go.uber.org/zap"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
)

func init() {
	cli_utils.SetInitFlags(StartDKG)
}

var StartDKG = &cobra.Command{
	Use:   "init",
	Short: "Initiates a DKG protocol",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		█████╗ ██╗  ██╗ ██████╗     ██╗███╗   ██╗██╗████████╗██╗ █████╗ ████████╗ ██████╗ ██████╗ 
		██╔══██╗██║ ██╔╝██╔════╝     ██║████╗  ██║██║╚══██╔══╝██║██╔══██╗╚══██╔══╝██╔═══██╗██╔══██╗
		██║  ██║█████╔╝ ██║  ███╗    ██║██╔██╗ ██║██║   ██║   ██║███████║   ██║   ██║   ██║██████╔╝
		██║  ██║██╔═██╗ ██║   ██║    ██║██║╚██╗██║██║   ██║   ██║██╔══██║   ██║   ██║   ██║██╔══██╗
		██████╔╝██║  ██╗╚██████╔╝    ██║██║ ╚████║██║   ██║   ██║██║  ██║   ██║   ╚██████╔╝██║  ██║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝╚═╝  ╚═══╝╚═╝   ╚═╝   ╚═╝╚═╝  ╚═╝   ╚═╝    ╚═════╝ ╚═╝  ╚═╝`)
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindInitFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator")
		if err != nil {
			return err
		}
		// Load operators TODO: add more sources.
		operatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		opMap, err := cli_utils.LoadOperators()
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		logger.Info("🔑 opening initiator RSA private key file")
		privateKey, encryptedRSAJSON, err := cli_utils.LoadRSAPrivKey()
		if err != nil {
			logger.Fatal("😥 Failed to load private key: ", zap.Error(err))
		}
		dkgInitiator := initiator.New(privateKey, opMap, logger)
		ethnetwork := e2m_core.MainNetwork
		if cli_utils.Network != "now_test_network" {
			ethnetwork = e2m_core.NetworkFromString(cli_utils.Network)
		}
		// create a new ID
		id := crypto.NewID()
		// start the ceremony
		depositData, keyShares, err := dkgInitiator.StartDKG(id, cli_utils.WithdrawAddress.Bytes(), operatorIDs, ethnetwork, cli_utils.OwnerAddress, cli_utils.Nonce)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		// Save deposit file
		logger.Info("🎯  All data is validated.")
		depositFinalPath := fmt.Sprintf("%s/deposit_%s-%v.json", cli_utils.OutputPath, depositData.PubKey, hex.EncodeToString(id[:]))
		logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
		err = utils.WriteJSON(depositFinalPath, []initiator.DepositDataJson{*depositData})
		if err != nil {
			logger.Warn("Failed writing deposit data file: ", zap.Error(err))
		}
		// Save results
		logger.Info("💾 Writing keyshares payload to file")
		err = cli_utils.WriteKeyShares(id, keyShares.Payload.PublicKey, keyShares)
		if err != nil {
			logger.Warn("Failed writing keyshares file: ", zap.Error(err))
		}
		if cli_utils.PrivKey == "" && cli_utils.GenerateInitiatorKey {
			rsaKeyPath := fmt.Sprintf("%s/encrypted_private_key-%v.json", cli_utils.OutputPath, depositData.PubKey)
			err = os.WriteFile(rsaKeyPath, encryptedRSAJSON, 0644)
			if err != nil {
				logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
			}
			if cli_utils.PrivKeyPassword == "" {
				rsaKeyPasswordPath := fmt.Sprintf("%s/password-%v.txt", cli_utils.OutputPath, depositData.PubKey)
				password, err := crypto.GenerateSecurePassword()
				if err != nil {
					logger.Fatal("Failed to generate secure password", zap.Error(err))
				}
				err = os.WriteFile(rsaKeyPasswordPath, []byte(password), 0644)
				if err != nil {
					logger.Fatal("Failed to write encrypted private key to file", zap.Error(err))
				}
			}
			logger.Info("Private key encrypted and stored at", zap.String("path", cli_utils.OutputPath))
		}

		fmt.Println(`
		▓█████▄  ██▓  ██████  ▄████▄   ██▓    ▄▄▄       ██▓ ███▄ ▄███▓▓█████  ██▀███  
		▒██▀ ██▌▓██▒▒██    ▒ ▒██▀ ▀█  ▓██▒   ▒████▄    ▓██▒▓██▒▀█▀ ██▒▓█   ▀ ▓██ ▒ ██▒
		░██   █▌▒██▒░ ▓██▄   ▒▓█    ▄ ▒██░   ▒██  ▀█▄  ▒██▒▓██    ▓██░▒███   ▓██ ░▄█ ▒
		░▓█▄   ▌░██░  ▒   ██▒▒▓▓▄ ▄██▒▒██░   ░██▄▄▄▄██ ░██░▒██    ▒██ ▒▓█  ▄ ▒██▀▀█▄  
		░▒████▓ ░██░▒██████▒▒▒ ▓███▀ ░░██████▒▓█   ▓██▒░██░▒██▒   ░██▒░▒████▒░██▓ ▒██▒
		 ▒▒▓  ▒ ░▓  ▒ ▒▓▒ ▒ ░░ ░▒ ▒  ░░ ▒░▓  ░▒▒   ▓▒█░░▓  ░ ▒░   ░  ░░░ ▒░ ░░ ▒▓ ░▒▓░
		 ░ ▒  ▒  ▒ ░░ ░▒  ░ ░  ░  ▒   ░ ░ ▒  ░ ▒   ▒▒ ░ ▒ ░░  ░      ░ ░ ░  ░  ░▒ ░ ▒░
		 ░ ░  ░  ▒ ░░  ░  ░  ░          ░ ░    ░   ▒    ▒ ░░      ░      ░     ░░   ░ 
		   ░     ░        ░  ░ ░          ░  ░     ░  ░ ░         ░      ░  ░   ░     
		 ░                   ░                                                        
		 
		 This tool was not audited.
		 When using distributed key generation you understand all the risks involved with
		 experimental cryptography.  
		 `)
		return nil
	},
}
