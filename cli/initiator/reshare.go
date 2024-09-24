package initiator

import (
	"fmt"
	"log"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/spf13/cobra"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
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
		signedProofs, err := wire.LoadProofs(cli_utils.ProofsFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
		}
		nonces, err := wire.LoadNonces(cli_utils.NoncesFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read nonces json file:", zap.Error(err))
		}
		if len(signedProofs) != len(nonces) {
			logger.Fatal("😥 Number of proofs and nonces do not match")
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
			// Contruct the resign message
			rMsg, err := dkgInitiator.ConstructReshareMessage(
				oldOperatorIDs,
				newOperatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				cli_utils.WithdrawAddress[:],
				cli_utils.OwnerAddress,
				nonces[i],
				signedProofs[i],
			)
			if err != nil {
				logger.Fatal("😥 Failed to construct resign message: ", zap.Error(err))
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
			1,
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
