package initiator

import (
	"fmt"
	"log"
	"os"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func init() {
	flags.SetGenerateReshareMsgFlags(GenerateReshareMsg)
	flags.SetReshareFlags(StartReshare)
}

var GenerateReshareMsg = &cobra.Command{
	Use:   "generate-reshare-msg",
	Short: "Generate reshare message hash for one or multiple ceremonies",
	RunE: func(cmd *cobra.Command, args []string) error {
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindGenerateReshareMsgFlags(cmd); err != nil {
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
		oldOperatorIDs, err := cli_utils.StringSliceToUintArray(flags.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		newOperatorIDs, err := cli_utils.StringSliceToUintArray(flags.NewOperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load new participants: ", zap.Error(err))
		}
		// create initiator instance
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, nil, true)
		if err != nil {
			return err
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
		ethNetwork := e2m_core.NetworkFromString(flags.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		rMsgs := []*wire.ReshareMessage{}
		for i := 0; i < len(signedProofs); i++ {
			nonce := flags.Nonce + uint64(i)
			// Construct reshare message
			rMsg, err := dkgInitiator.ConstructReshareMessage(
				oldOperatorIDs,
				newOperatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				flags.WithdrawAddress[:],
				flags.OwnerAddress,
				nonce,
				flags.Amount,
				signedProofs[i],
			)
			if err != nil {
				logger.Fatal("😥 Failed to construct reshare message: ", zap.Error(err))
			}
			rMsgs = append(rMsgs, rMsg)
		}
		// write bulk reshare message hex to file
		msgHex, err := utils.GetMessageString(rMsgs)
		if err != nil {
			logger.Fatal("😥 Failed to marshal reshare message hash:", zap.Error(err))
		}
		finalPath := fmt.Sprintf("%s/reshare.txt", flags.OutputPath)
		err = os.WriteFile(finalPath, []byte(msgHex), 0o600)
		if err != nil {
			logger.Fatal("😥 Failed to save reshare message hash:", zap.Error(err))
		}
		logger.Info("🚀 Reshare message hash generated", zap.String("path", finalPath))
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
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindReshareFlags(cmd); err != nil {
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
		oldOperatorIDs, err := cli_utils.StringSliceToUintArray(flags.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		newOperatorIDs, err := cli_utils.StringSliceToUintArray(flags.NewOperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load new participants: ", zap.Error(err))
		}
		// create a new ID for resharing
		id := spec.NewID()
		// create initiator instance
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, flags.ClientCACertPath, flags.TLSInsecure)
		if err != nil {
			return err
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
		ethNetwork := e2m_core.NetworkFromString(flags.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		signatures, err := cli_utils.SignaturesStringToBytes(flags.Signatures)
		if err != nil {
			logger.Fatal("😥 Failed to load signatures: ", zap.Error(err))
		}
		rMsgs := []*wire.ReshareMessage{}
		for i := 0; i < len(signedProofs); i++ {
			nonce := flags.Nonce + uint64(i)
			// Contruct the reshare message
			rMsg, err := dkgInitiator.ConstructReshareMessage(
				oldOperatorIDs,
				newOperatorIDs,
				signedProofs[i][0].Proof.ValidatorPubKey,
				ethNetwork,
				flags.WithdrawAddress[:],
				flags.OwnerAddress,
				nonce,
				flags.Amount,
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
			flags.OwnerAddress,
			flags.Nonce,
			flags.WithdrawAddress,
			flags.OutputPath,
		); err != nil {
			logger.Fatal("Could not save results", zap.Error(err))
		}
		logger.Info("🚀 Resharing ceremony completed")
		return nil
	},
}
