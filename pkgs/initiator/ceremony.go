package initiator

import (
	"context"
	"encoding/hex"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sourcegraph/conc/pool"
	spec "github.com/ssvlabs/dkg-spec"
	cli_utils "github.com/ssvlabs/ssv-dkg/cli/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"
)

const (
	// maxConcurrency is the maximum number of DKG inits to run concurrently.
	maxConcurrency = 20
)

type Result struct {
	id          [24]byte
	nonce       uint64
	depositData *wire.DepositDataCLI
	keyShares   *wire.KeySharesCLI
	proof       []*wire.SignedProof
}

func StartInitCeremony(ctx context.Context, logger *zap.Logger, opMap wire.OperatorsCLI, operatorIDs []uint64, ownerAddress, withdrawAddress common.Address, nonce, amount, validators uint64, ethNetwork e2m_core.Network, clientCACertPath []string, tlsInsecure bool, outputPath, ver string) {
	pool := pool.NewWithResults[*Result]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxConcurrency)
	for i := 0; i < int(validators); i++ {
		i := i
		pool.Go(func(ctx context.Context) (*Result, error) {
			// Create new DKG initiator
			dkgInitiator, err := New(opMap.Clone(), logger, ver, clientCACertPath, tlsInsecure)
			if err != nil {
				return nil, err
			}
			// Create a new ID.
			id := spec.NewID()
			nonce := nonce + uint64(i)
			// Perform the ceremony.
			depositData, keyShares, proofs, err := dkgInitiator.StartDKG(id, withdrawAddress.Bytes(), operatorIDs, ethNetwork, ownerAddress, nonce, amount)
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
		int(validators),
		ownerAddress,
		nonce,
		withdrawAddress,
		outputPath,
	); err != nil {
		logger.Fatal("Could not save results", zap.Error(err))
	}
	logger.Info("🚀 DKG ceremony completed")
}
