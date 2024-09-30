package initiator

import (
	"encoding/json"
	"fmt"
	"log"
	"os"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/spf13/cobra"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
)

func init() {
	cli_utils.SetGenerateReshareMsgFlags(GenerateReshareMsg)
	cli_utils.SetReshareFlags(StartReshare)
}

var GenerateReshareMsg = &cobra.Command{
	Use:   "generate-reshare-msg",
	Short: "Generate reshare message for one or multiple ceremonies",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindGenerateReshareMsgFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator")
		if err != nil {
			return err
		}
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		oldOperatorIDs, err := cli_utils.StringSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		newOperatorIDs, err := cli_utils.StringSliceToUintArray(cli_utils.NewOperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load new participants: ", zap.Error(err))
		}
		// create initiator instance
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
		if err != nil {
			return err
		}
		var signedProofs [][]*spec.SignedProof
		if cli_utils.ProofsFilePath != "" {
			signedProofs, err = wire.LoadProofs(cli_utils.ProofsFilePath)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
			}
		}
		if cli_utils.ProofsString != "" {
			signedProofs, err = cli_utils.DecodeProofsString(cli_utils.ProofsString)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs string:", zap.Error(err))
			}
		}
		ethNetwork := e2m_core.NetworkFromString(cli_utils.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		rMsgs := []*wire.ReshareMessage{}
		for i := 0; i < len(signedProofs); i++ {
			nonce := cli_utils.Nonce + uint64(i)
			// Contruct the resign message
			rMsg, err := dkgInitiator.ConstructReshareMessage(
				oldOperatorIDs,
				newOperatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				cli_utils.WithdrawAddress[:],
				cli_utils.OwnerAddress,
				nonce,
				signedProofs[i],
			)
			if err != nil {
				logger.Fatal("😥 Failed to construct reshare message: ", zap.Error(err))
			}
			rMsgs = append(rMsgs, rMsg)
		}
		// write bulk reshare message to file
		rMsgBytes, err := json.Marshal(rMsgs)
		if err != nil {
			logger.Fatal("😥 Failed to marshal reshare messages:", zap.Error(err))
		}
		finalPath := fmt.Sprintf("%s/reshare.json", cli_utils.OutputPath)
		err = os.WriteFile(finalPath, rMsgBytes, 0o600)
		if err != nil {
			logger.Fatal("😥 Failed to save reshare messages:", zap.Error(err))
		}
		logger.Info("🚀 Reshare message generated", zap.String("path", finalPath))
		return nil
	},
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
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		oldOperatorIDs, err := cli_utils.StringSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		newOperatorIDs, err := cli_utils.StringSliceToUintArray(cli_utils.NewOperatorIDs)
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
		var signedProofs [][]*spec.SignedProof
		if cli_utils.ProofsFilePath != "" {
			signedProofs, err = wire.LoadProofs(cli_utils.ProofsFilePath)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
			}
		}
		if cli_utils.ProofsString != "" {
			signedProofs, err = cli_utils.DecodeProofsString(cli_utils.ProofsString)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs string:", zap.Error(err))
			}
		}
		ethNetwork := e2m_core.NetworkFromString(cli_utils.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		signatures, err := cli_utils.SignaturesStringToBytes(cli_utils.Signatures)
		if err != nil {
			logger.Fatal("😥 Failed to load signatures: ", zap.Error(err))
		}
		rMsgs := []*wire.ReshareMessage{}
		for i := 0; i < len(signedProofs); i++ {
			nonce := cli_utils.Nonce + uint64(i)
			// Contruct the reshare message
			rMsg, err := dkgInitiator.ConstructReshareMessage(
				oldOperatorIDs,
				newOperatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				cli_utils.WithdrawAddress[:],
				cli_utils.OwnerAddress,
				nonce,
				signedProofs[i],
			)
			if err != nil {
				logger.Fatal("😥 Failed to construct reshare message: ", zap.Error(err))
			}
			rMsgs = append(rMsgs, rMsg)
		}
		// Append the signatures
		signedReshare := &wire.SignedReshare{
			Messages:  rMsgs,
			Signature: signatures,
		}
		// Start the ceremony
		depositData, keyShares, proofs, err := dkgInitiator.StartResharing(id, signedReshare)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		// Save results
		logger.Info("🎯 All data is validated.")
		if err := cli_utils.WriteResults(
			logger,
			depositData,
			keyShares,
			proofs,
			false,
			len(signedProofs),
			cli_utils.OwnerAddress,
			cli_utils.Nonce,
			cli_utils.WithdrawAddress,
			cli_utils.OutputPath,
		); err != nil {
			logger.Fatal("Could not save results", zap.Error(err))
		}
		logger.Info("🚀 Resharing ceremony completed")
		return nil
	},
}
