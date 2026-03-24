package initiator

import (
	"fmt"
	"log"
	"os"

	"github.com/spf13/cobra"
	e2m_core "github.com/ssvlabs/eth2-key-manager/core"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func init() {
	flags.SetGenerateResignMsgFlags(GenerateResignMsg)
	flags.SetResigningFlags(StartResigning)
}

var GenerateResignMsg = &cobra.Command{
	Use:   "generate-resign-msg",
	Short: "Generate resign message hash for one or multiple ceremonies",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindGenerateResignMsgFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator", flags.LogFilePath, flags.LogLevel, flags.LogFormat, flags.LogLevelFormat)
		if err != nil {
			return err
		}
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		opMap, err := cli_utils.LoadOperators(logger, flags.OperatorsInfo, flags.OperatorsInfoPath)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		operatorIDs, err := cli_utils.StringSliceToUintArray(flags.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		ethNetwork, err := e2m_core.NetworkFromString(flags.Network)
		if err != nil {
			logger.Fatal("😥 Cant recognize eth network", zap.Error(err))
		}
		var signedProofs [][]*spec.SignedProof
		if flags.ProofsFilePath != "" {
			signedProofs, err = wire.LoadProofs(flags.ProofsFilePath)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
			}
		}
		if flags.ProofsString != "" {
			signedProofs, err = cli_utils.DecodeProofsString(flags.ProofsString)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs string:", zap.Error(err))
			}
		}
		// Create new DKG initiator
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, nil, true)
		if err != nil {
			return err
		}
		// Reconstruct the resign messages
		rMsgs := []*wire.ResignMessage{}
		for i := 0; i < len(signedProofs); i++ {
			nonce := flags.Nonce + uint64(i)
			rMsg, err := dkgInitiator.ConstructResignMessage(
				operatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				flags.WithdrawalCredentials(),
				flags.OwnerAddress,
				nonce,
				flags.Amount,
				signedProofs[i],
			)
			if err != nil {
				logger.Fatal("😥 Failed to construct resign message:", zap.Error(err))
			}
			rMsgs = append(rMsgs, rMsg)
		}
		// Save the resign messages
		msgHex, err := utils.GetMessageString(rMsgs)
		if err != nil {
			logger.Fatal("😥 Failed to marshal resign message hash:", zap.Error(err))
		}
		finalPath := fmt.Sprintf("%s/resign.txt", flags.OutputPath)
		err = os.WriteFile(finalPath, []byte(msgHex), 0o600)
		if err != nil {
			logger.Fatal("😥 Failed to save resign message hash:", zap.Error(err))
		}
		logger.Info("🚀 Resign message hash generated", zap.String("path", finalPath))
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

		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindResigningFlags(cmd); err != nil {
			return err
		}
		logger, err := cli_utils.SetGlobalLogger(cmd, "dkg-initiator", flags.LogFilePath, flags.LogLevel, flags.LogFormat, flags.LogLevelFormat)
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
		opMap, err := cli_utils.LoadOperators(logger, flags.OperatorsInfo, flags.OperatorsInfoPath)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		operatorIDs, err := cli_utils.StringSliceToUintArray(flags.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load operator IDs: ", zap.Error(err))
		}
		ethNetwork, err := e2m_core.NetworkFromString(flags.Network)
		if err != nil {
			logger.Fatal("😥 Cant recognize eth network", zap.Error(err))
		}
		var signedProofs [][]*spec.SignedProof
		if flags.ProofsFilePath != "" {
			signedProofs, err = wire.LoadProofs(flags.ProofsFilePath)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
			}
		}
		if flags.ProofsString != "" {
			signedProofs, err = cli_utils.DecodeProofsString(flags.ProofsString)
			if err != nil {
				logger.Fatal("😥 Failed to read proofs string:", zap.Error(err))
			}
		}
		signatures, err := cli_utils.SignaturesStringToBytes(flags.Signatures)
		if err != nil {
			logger.Fatal("😥 Failed to load signatures: ", zap.Error(err))
		}
		// Create new DKG initiator
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, flags.ClientCACertPath, flags.TLSInsecure)
		if err != nil {
			return err
		}
		// Create a new ID.
		id := spec.NewID()
		// Reconstruct the resign messages
		rMsgs := []*wire.ResignMessage{}
		for i := 0; i < len(signedProofs); i++ {
			nonce := flags.Nonce + uint64(i)
			rMsg, err := dkgInitiator.ConstructResignMessage(
				operatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				flags.WithdrawalCredentials(),
				flags.OwnerAddress,
				nonce, flags.Amount,
				signedProofs[i],
			)
			if err != nil {
				logger.Fatal("😥 Failed to construct resign message:", zap.Error(err))
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
			len(signedProofs),
			flags.OwnerAddress,
			flags.Nonce,
			flags.WithdrawAddress,
			flags.OutputPath,
		); err != nil {
			logger.Fatal("Could not save results", zap.Error(err))
		}
		logger.Info("🚀 Resigning ceremony completed")
		return nil
	},
}
