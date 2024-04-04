package initiator

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

const (
	// maxConcurrency is the maximum number of DKG inits to run concurrently.
	maxConcurrency = 20
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
		defer func() {
			if err := cli_utils.Sync(logger); err != nil {
				log.Printf("Failed to sync logger: %v", err)
			}
		}()
		logger.Info("🪛 Initiator`s", zap.String("Version", cmd.Version))
		// Load operators TODO: add more sources.
		operatorIDs, err := cli_utils.StingSliceToUintArray(cli_utils.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		opMap, err := cli_utils.LoadOperators(logger)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		logger.Info("🔑 opening initiator RSA private key file")
		ethnetwork := e2m_core.MainNetwork
		if cli_utils.Network != "now_test_network" {
			ethnetwork = e2m_core.NetworkFromString(cli_utils.Network)
		}
		// start the ceremony
		ctx := context.Background()
		pool := pool.NewWithResults[*Result]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxConcurrency)
		for i := 0; i < int(cli_utils.Validators); i++ {
			i := i
			pool.Go(func(ctx context.Context) (*Result, error) {
				// Create new DKG initiator
				dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, cli_utils.ClientCACertPath)
				if err != nil {
					return nil, err
				}
				// Create a new ID.
				id := crypto.NewID()
				nonce := cli_utils.Nonce + uint64(i)
				// Perform the ceremony.
				depositData, keyShares, proofs, err := dkgInitiator.StartDKG(id, cli_utils.WithdrawAddress.Bytes(), operatorIDs, ethnetwork, cli_utils.OwnerAddress, nonce)
				if err != nil {
					return nil, err
				}
				logger.Debug("DKG ceremony completed",
					zap.String("id", hex.EncodeToString(id[:])),
					zap.Uint64("nonce", nonce),
					zap.String("pubkey", depositData.PubKey),
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
			logger.Fatal("😥 Failed to initiate DKG ceremony: ", zap.Error(err))
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
			int(cli_utils.Validators),
			cli_utils.OwnerAddress,
			cli_utils.Nonce,
			cli_utils.WithdrawAddress,
			cli_utils.OutputPath,
		); err != nil {
			logger.Fatal("Could not save results", zap.Error(err))
		}
		logger.Info("🚀 DKG ceremony completed")
		return nil
	},
}

type Result struct {
	id          [24]byte
	nonce       uint64
	depositData *wire.DepositDataCLI
	keyShares   *wire.KeySharesCLI
	proof       []*wire.SignedProof
}
