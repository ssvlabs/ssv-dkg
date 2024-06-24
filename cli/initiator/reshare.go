package initiator

import (
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/spf13/cobra"
	spec "github.com/ssvlabs/dkg-spec"
	"go.uber.org/zap"
)

func init() {
	cli_utils.SetReshareFlags(StartReshare)
}

var StartReshare = &cobra.Command{
	Use:   "reshare",
	Short: "Reshare an existing key to new operators",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		▓█████▄  ██ ▄█▀  ▄████     ██▀███  ▓█████   ██████  ██░ ██  ▄▄▄       ██▀███  ▓█████ 
		▒██▀ ██▌ ██▄█▒  ██▒ ▀█▒   ▓██ ▒ ██▒▓█   ▀ ▒██    ▒ ▓██░ ██▒▒████▄    ▓██ ▒ ██▒▓█   ▀ 
		░██   █▌▓███▄░ ▒██░▄▄▄░   ▓██ ░▄█ ▒▒███   ░ ▓██▄   ▒██▀▀██░▒██  ▀█▄  ▓██ ░▄█ ▒▒███   
		░▓█▄   ▌▓██ █▄ ░▓█  ██▓   ▒██▀▀█▄  ▒▓█  ▄   ▒   ██▒░▓█ ░██ ░██▄▄▄▄██ ▒██▀▀█▄  ▒▓█  ▄ 
		░▒████▓ ▒██▒ █▄░▒▓███▀▒   ░██▓ ▒██▒░▒████▒▒██████▒▒░▓█▒░██▓ ▓█   ▓██▒░██▓ ▒██▒░▒████▒
		▒▒▓  ▒ ▒ ▒▒ ▓▒ ░▒   ▒    ░ ▒▓ ░▒▓░░░ ▒░ ░▒ ▒▓▒ ▒ ░ ▒ ░░▒░▒ ▒▒   ▓▒█░░ ▒▓ ░▒▓░░░ ▒░ ░
		░ ▒  ▒ ░ ░▒ ▒░  ░   ░      ░▒ ░ ▒░ ░ ░  ░░ ░▒  ░ ░ ▒ ░▒░ ░  ▒   ▒▒ ░  ░▒ ░ ▒░ ░ ░  ░
		░ ░  ░ ░ ░░ ░ ░ ░   ░      ░░   ░    ░   ░  ░  ░   ░  ░░ ░  ░   ▒     ░░   ░    ░   
		░    ░  ░         ░       ░        ░  ░      ░   ░  ░  ░      ░  ░   ░        ░  ░
		░`)
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindReshareFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator")
		if err != nil {
			return err
		}
		defer logger.Sync()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		oldOperatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		newOperatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.NewOperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load new participants: ", zap.Error(err))
		}
		// create a new ID for resharing
		id := spec.NewID()
		// create initiator instance
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
		if err != nil {
			return err
		}
		signedProofs, err := wire.LoadProofs(cli_utils.ProofsFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
		}
		proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
		ethnetwork := e2m_core.MainNetwork
		if cli_utils.Network != "now_test_network" {
			ethnetwork = e2m_core.NetworkFromString(cli_utils.Network)
		}

		// Open ethereum keystore
		jsonBytes, err := os.ReadFile(cli_utils.KeystorePath)
		if err != nil {
			return err
		}
		keyStorePassword, err := os.ReadFile(filepath.Clean(cli_utils.KeystorePass))
		if err != nil {
			return fmt.Errorf("😥 Error reading password file: %s", err)
		}
		sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
		if err != nil {
			return err
		}
		reshareMsg, err := dkgInitiator.ConstructReshareMessage(
			oldOperatorIDs,
			newOperatorIDs,
			proofsData[0].Proof.ValidatorPubKey,
			ethnetwork,
			cli_utils.WithdrawAddress.Bytes(),
			cli_utils.OwnerAddress,
			cli_utils.Nonce,
			sk.PrivateKey,
			proofsData)
		if err != nil {
			return err
		}
		logger.Info("🚀 Starting Re-SHARING ceremony", zap.Uint64s("old operator IDs", oldOperatorIDs), zap.Uint64s("new operator IDs", newOperatorIDs), zap.String("instance_id", hex.EncodeToString(id[:])))
		logger.Info("Outgoing reshare request fields",
			zap.Any("Old operator IDs", oldOperatorIDs),
			zap.Any("New operator IDs", newOperatorIDs),
			zap.String("ValidatorPubKey", hex.EncodeToString(reshareMsg.Proofs[0].Proof.ValidatorPubKey)),
			zap.String("network", hex.EncodeToString(reshareMsg.SignedReshare.Reshare.Fork[:])),
			zap.String("withdrawal", hex.EncodeToString(reshareMsg.SignedReshare.Reshare.WithdrawalCredentials)),
			zap.String("owner", hex.EncodeToString(reshareMsg.SignedReshare.Reshare.Owner[:])),
			zap.Uint64("nonce", reshareMsg.SignedReshare.Reshare.Nonce),
			zap.String("EIP1271 owner signature", hex.EncodeToString(reshareMsg.SignedReshare.Signature)))
		for _, proof := range reshareMsg.Proofs {
			logger.Info("Loaded proof",
				zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
				zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
				zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
				zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
				zap.String("Signature", hex.EncodeToString(proof.Signature)))
		}
		// Start the ceremony
		depositData, keyShares, proof, err := dkgInitiator.StartResharing(id, reshareMsg)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		var depositDataArr []*wire.DepositDataCLI
		var keySharesArr []*wire.KeySharesCLI
		var proofs [][]*wire.SignedProof
		depositDataArr = append(depositDataArr, depositData)
		keySharesArr = append(keySharesArr, keyShares)
		proofs = append(proofs, proof)
		// Save results
		logger.Info("🎯 All data is validated.")
		if err := cli_utils.WriteResults(
			logger,
			depositDataArr,
			keySharesArr,
			proofs,
			false,
			1,
			cli_utils.OwnerAddress,
			cli_utils.Nonce,
			cli_utils.WithdrawAddress,
			cli_utils.OutputPath,
		); err != nil {
			logger.Fatal("Could not save results", zap.Error(err))
		}
		logger.Info("🚀 Resigning ceremony completed")
		return nil
	},
}
