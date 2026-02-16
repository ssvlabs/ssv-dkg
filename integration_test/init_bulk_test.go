package integration_test

import (
	"context"
	"fmt"
	"runtime"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/sourcegraph/conc/pool"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

type bulkResult struct {
	depositData *wire.DepositDataCLI
	keyShares   *wire.KeySharesCLI
	proofs      []*wire.SignedProof
}

func runBulkInit(t *testing.T, ops wire.OperatorsCLI, opIDs []uint64, owner, withdraw [20]byte, valCount int) {
	t.Helper()
	logger := zap.L().Named("integration-tests")

	ctx := context.Background()
	// Scale concurrency to available CPUs: the DKG protocol uses a 10-second
	// TimePhaser per phase, so deal round-trips must complete within that window.
	// Under parallel test execution (4 test groups) with -race overhead, too many
	// concurrent ceremonies saturate the CPU and cause spurious phase-timeout complaints.
	maxGoroutines := max(2, runtime.GOMAXPROCS(0)/2)
	p := pool.NewWithResults[*bulkResult]().WithContext(ctx).WithFirstError().WithMaxGoroutines(maxGoroutines)
	for i := 0; i < valCount; i++ {
		i := i
		p.Go(func(ctx context.Context) (*bulkResult, error) {
			clnt, err := initiator.New(ops.Clone(), logger, testVersion, rootCert, false)
			if err != nil {
				return nil, err
			}
			id := spec.NewID()
			depositData, ks, proofs, err := clnt.StartDKG(id, withdraw[:], opIDs, "mainnet", owner, uint64(1+i), uint64(spec_crypto.MIN_ACTIVATION_BALANCE)) //nolint:gosec // test values
			if err != nil {
				return nil, err
			}
			return &bulkResult{depositData: depositData, keyShares: ks, proofs: proofs}, nil
		})
	}
	results, err := p.Wait()
	require.NoError(t, err)

	var depositDataArr []*wire.DepositDataCLI
	var keySharesArr []*wire.KeySharesCLI
	var proofsArr [][]*wire.SignedProof
	for _, r := range results {
		depositDataArr = append(depositDataArr, r.depositData)
		keySharesArr = append(keySharesArr, r.keyShares)
		proofsArr = append(proofsArr, r.proofs)
	}
	aggKs, err := initiator.GenerateAggregatesKeyshares(keySharesArr)
	require.NoError(t, err)
	err = validator.ValidateResults(depositDataArr, aggKs, proofsArr, valCount, owner, 1, withdraw)
	require.NoError(t, err)
}

func TestBulkHappyFlows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name  string
		opIDs []uint64
	}{
		{"4 operators", []uint64{11, 22, 33, 44}},
		{"7 operators", []uint64{11, 22, 33, 44, 55, 66, 77}},
		{"10 operators", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}},
		{"13 operators", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			stubClient := &stubs.Client{
				CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
					return nil, nil
				},
			}
			servers, ops := createOperators(t, testVersion, stubClient)
			t.Cleanup(func() {
				for _, srv := range servers {
					srv.HttpSrv.Close()
				}
			})
			withdraw := newEthAddress(t)
			owner := newEthAddress(t)
			for _, valCount := range []int{1, 10, 30} {
				t.Run(fmt.Sprintf("%d validators", valCount), func(t *testing.T) {
					runBulkInit(t, ops, tc.opIDs, owner, withdraw, valCount)
				})
			}
		})
	}
}
