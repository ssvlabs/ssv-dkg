package initiator

import (
	"context"
	"encoding/hex"
	"fmt"
	"log"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/sourcegraph/conc/pool"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/cli/flags"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

const (
	// maxConcurrency is the maximum number of DKG inits to run concurrently.
	maxConcurrency = 20
)

func init() {
	flags.SetInitFlags(StartDKG)
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
		if err := flags.SetViperConfig(cmd); err != nil {
			return err
		}
		if err := flags.BindInitFlags(cmd); err != nil {
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
		// Load operators TODO: add more sources.
		operatorIDs, err := cli_utils.StringSliceToUintArray(flags.OperatorIDs)
		if err != nil {
			logger.Fatal("😥 Failed to load participants: ", zap.Error(err))
		}
		opMap, err := cli_utils.LoadOperators(logger, flags.OperatorsInfo, flags.OperatorsInfoPath)
		if err != nil {
			logger.Fatal("😥 Failed to load operators: ", zap.Error(err))
		}
		ethNetwork := e2m_core.NetworkFromString(flags.Network)
		if ethNetwork == "" {
			logger.Fatal("😥 Cant recognize eth network")
		}
		// start the ceremony
		ctx := context.Background()
		pool := pool.NewWithResults[*Result]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxConcurrency)
		for i := 0; i < int(flags.Validators); i++ {
			i := i
			pool.Go(func(ctx context.Context) (*Result, error) {
				// Create new DKG initiator
				dkgInitiator, err := initiator.New(opMap.Clone(), logger, cmd.Version, flags.ClientCACertPath, flags.TLSInsecure)
				if err != nil {
					return nil, err
				}
				// Create a new ID.
				id := spec.NewID()
				nonce := flags.Nonce + uint64(i)
				// Perform the ceremony.
				depositData, keyShares, proofs, err := dkgInitiator.StartDKG(id, flags.WithdrawAddress.Bytes(), operatorIDs, ethNetwork, flags.OwnerAddress, nonce, flags.Amount)
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
			int(flags.Validators),
			flags.OwnerAddress,
			flags.Nonce,
			flags.WithdrawAddress,
			flags.OutputPath,
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
