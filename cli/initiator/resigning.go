package initiator

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
)

func init() {
	cli_utils.SetResigningFlags(StartResigning)
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
		signatures, err := cli_utils.SignaturesStringToBytes(cli_utils.Signatures)
		if err != nil {
			logger.Fatal("😥 Failed to load signatures: ", zap.Error(err))
		}
		// start the ceremony
		ctx := context.Background()
		pool := pool.NewWithResults[*Result]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxConcurrency)
		for i := 0; i < len(arrayOfSignedProofs); i++ {
			i := i
			pool.Go(func(ctx context.Context) (*Result, error) {
				// Create new DKG initiator
				dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
				if err != nil {
					return nil, err
				}
				// Create a new ID.
				id := spec.NewID()
				nonce := cli_utils.Nonce + uint64(i)
				// Reconstruct the resign message
				rMsg, err := dkgInitiator.ConstructResignMessage(
					operatorIDs,
					arrayOfSignedProofs[i][0].Proof.ValidatorPubKey,
					ethNetwork,
					cli_utils.WithdrawAddress[:],
					cli_utils.OwnerAddress,
					nonce,
					arrayOfSignedProofs[i],
				)
				if err != nil {
					return nil, err
				}
				// Append the signatures
				signedResign := &wire.SignedResign{
					Message:   rMsg,
					Signature: signatures,
				}
				// Perform the resigning ceremony
				depositData, keyShares, proofs, err := dkgInitiator.StartResigning(id, signedResign)
				if err != nil {
					return nil, err
				}
				logger.Debug("Resigning ceremony completed",
					zap.String("id", hex.EncodeToString(id[:])),
					zap.Uint64("nonce", nonce),
					zap.String("pubkey", keyShares.Shares[0].ShareData.PublicKey),
				)
				return &Result{
					id:          id,
					depositData: depositData,
					keyShares:   keyShares,
					nonce:       nonce,
					proof:       proofs,
				}, nil
			})
		}
		results, err := pool.Wait()
		if err != nil {
			logger.Fatal("😥 Failed to initiate Resigning ceremony: ", zap.Error(err))
		}
		var depositDataArr []*wire.DepositDataCLI
		var keySharesArr []*wire.KeySharesCLI
		var proofs [][]*wire.SignedProof
		for _, res := range results {
			depositDataArr = append(depositDataArr, res.depositData)
			keySharesArr = append(keySharesArr, res.keyShares)
			proofs = append(proofs, res.proof)
		}
		// Save results
		logger.Info("🎯 All data is validated.")
		if err := cli_utils.WriteResults(
			logger,
			depositDataArr,
			keySharesArr,
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
