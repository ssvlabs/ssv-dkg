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
)

func init() {
	cli_utils.SetReshareFlags(generateBulkReshareMsg)
}

var generateBulkReshareMsg = &cobra.Command{
	Use:   "prepare bulk reshare",
	Short: "Generates bulk reshare message containing an array of reshare messages",
	RunE: func(cmd *cobra.Command, args []string) error {
		fmt.Println(`
		░▒█▀▀▄░▒█░▒█░▒█░░░░▒█░▄▀░░░▒█▀▀▄░▒█▀▀▀░▒█▀▀▀█░▒█░▒█░█▀▀▄░▒█▀▀▄░▒█▀▀▀
		░▒█▀▀▄░▒█░▒█░▒█░░░░▒█▀▄░░░░▒█▄▄▀░▒█▀▀▀░░▀▀▀▄▄░▒█▀▀█▒█▄▄█░▒█▄▄▀░▒█▀▀▀
		░▒█▄▄█░░▀▄▄▀░▒█▄▄█░▒█░▒█░░░▒█░▒█░▒█▄▄▄░▒█▄▄▄█░▒█░▒█▒█░▒█░▒█░▒█░▒█▄▄▄
		`)
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
		oldOperatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		newOperatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.NewOperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load new participants: ", zap.Error(err))
		}
		// create initiator instance
		dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
		if err != nil {
			return err
		}
		signedProofs, err := wire.LoadProofs(cli_utils.ProofsFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read proofs json file:", zap.Error(err))
		}
		ethNetwork := e2m_core.NetworkFromString(cli_utils.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		nonces, err := wire.LoadNonces(cli_utils.NoncesFilePath)
		if err != nil {
			logger.Fatal("😥 Failed to read nonces json file:", zap.Error(err))
		}
		bulkReshareMsg, err := dkgInitiator.ConstructBulkReshareMessasge(oldOperatorIDs, newOperatorIDs, signedProofs, ethNetwork, cli_utils.WithdrawAddress[:], cli_utils.OwnerAddress, nonces)
		if err != nil {
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
		}
		// write bulk reshare message to file
		if err := cli_utils.WriteBulkReshareMessage(
			logger,
			bulkReshareMsg,
			cli_utils.OutputPath,
		); err != nil {
			logger.Fatal("Could not save results", zap.Error(err))
		}
		logger.Info("🚀 Resharing ceremony completed")
		return nil
	},
}
