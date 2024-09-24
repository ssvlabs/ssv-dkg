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
	cli_utils.SetGenerateResignMsgFlags(GenerateResignMsg)
	cli_utils.SetResigningFlags(StartResigning)
}

var GenerateResignMsg = &cobra.Command{
	Use:   "generate-resign-msg",
	Short: "Generate resign message for one or multiple ceremonies",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindResigningFlags(cmd); err != nil {
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
		operatorIDs, err := cli_utils.StringSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		ethNetwork := e2m_core.NetworkFromString(cli_utils.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		arrayOfSignedProofs, err := wire.LoadProofs(cli_utils.ProofsFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
		}
		nonces, err := wire.LoadNonces(cli_utils.NoncesFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read nonces json file:", zap.Error(err))
		}
		if len(arrayOfSignedProofs) != len(nonces) {
			logger.Fatal("😥 Number of proofs and nonces do not match")
		}
		// Create new DKG initiator
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
		if err != nil {
			return err
		}
		// Reconstruct the resign messages
		rMsgs := []*wire.ResignMessage{}
		for i := 0; i < len(arrayOfSignedProofs); i++ {
			rMsg, err := dkgInitiator.ConstructResignMessage(
				operatorIDs,
				arrayOfSignedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				cli_utils.WithdrawAddress[:],
				cli_utils.OwnerAddress,
				nonces[i],
				arrayOfSignedProofs[i],
			)
			if err != nil {
				return err
			}
			rMsgs = append(rMsgs, rMsg)
		}
		// Save the resign messages
		if err := cli_utils.WriteMessage(rMsgs, cli_utils.OutputPath, "resign"); err != nil {
			logger.Fatal("😥 Failed to save resign messages:", zap.Error(err))
		}
		logger.Info("🚀 Resign messages generated")
		return nil
	},
}

var StartResigning = &cobra.Command{
	Use:   "resign",
	Short: "Resigning DKG results",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		██████╗ ██╗  ██╗ ██████╗     ██████╗ ███████╗███████╗██╗ ██████╗ ███╗   ██╗
		██╔══██╗██║ ██╔╝██╔════╝     ██╔══██╗██╔════╝██╔════╝██║██╔════╝ ████╗  ██║
		██║  ██║█████╔╝ ██║  ███╗    ██████╔╝█████╗  ███████╗██║██║  ███╗██╔██╗ ██║
		██║  ██║██╔═██╗ ██║   ██║    ██╔══██╗██╔══╝  ╚════██║██║██║   ██║██║╚██╗██║
		██████╔╝██║  ██╗╚██████╔╝    ██║  ██║███████╗███████║██║╚██████╔╝██║ ╚████║
		╚═════╝ ╚═╝  ╚═╝ ╚═════╝     ╚═╝  ╚═╝╚══════╝╚══════╝╚═╝ ╚═════╝ ╚═╝  ╚═══╝
																				`)

		if err := cli_utils.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := cli_utils.BindResigningFlags(cmd); err != nil {
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
		// Load operators
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		operatorIDs, err := cli_utils.StringSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		ethNetwork := e2m_core.NetworkFromString(cli_utils.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		arrayOfSignedProofs, err := wire.LoadProofs(cli_utils.ProofsFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
		}
		nonces, err := wire.LoadNonces(cli_utils.NoncesFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read nonces json file:", zap.Error(err))
		}
		if len(arrayOfSignedProofs) != len(nonces) {
			logger.Fatal("😥 Number of proofs and nonces do not match")
		}
		signatures, err := cli_utils.SignaturesStringToBytes(cli_utils.Signatures)
		if err != nil {
			logger.Fatal("😥 Failed to load signatures: ", zap.Error(err))
		}
		// Create new DKG initiator
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
		if err != nil {
			return err
		}
		// Create a new ID.
		id := spec.NewID()
		// Reconstruct the resign messages
		rMsgs := []*wire.ResignMessage{}
		for i := 0; i < len(arrayOfSignedProofs); i++ {
			rMsg, err := dkgInitiator.ConstructResignMessage(
				operatorIDs,
				arrayOfSignedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				cli_utils.WithdrawAddress[:],
				cli_utils.OwnerAddress,
				nonces[i],
				arrayOfSignedProofs[i],
			)
			if err != nil {
				return err
			}
			rMsgs = append(rMsgs, rMsg)
		}
		// Append the signatures
		signedResign := &wire.SignedResign{
			Messages:  rMsgs,
			Signature: signatures,
		}
		// Perform the resigning ceremony
		depositData, keyShares, proofs, err := dkgInitiator.StartResigning(id, signedResign)
		if err != nil {
			return err
		}
		// Save results
		logger.Info("🎯 All data is validated.")
		if err := cli_utils.WriteResults(
			logger,
			depositData,
			keyShares,
			proofs,
			false,
			len(arrayOfSignedProofs),
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
