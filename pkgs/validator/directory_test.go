package validator

import (
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
)

func TestOpenResultsDir(t *testing.T) {
	tests := []struct {
		path                   string
		expectedErr            string
		expectedValidatorCount int
		expectedAggregations   bool
		expectedNonces         []uint64
		expectedPubkeys        []string
	}{
		{
			path:                   "testdata/results--valid-1",
			expectedErr:            "",
			expectedValidatorCount: 1,
			expectedAggregations:   false,
			expectedNonces:         []uint64{2731},
			expectedPubkeys:        []string{"864f476741fe922a195b97a200a8232a5396fd035597e8ba77ab18c2e5dfc4d66652e4e2975f0c605aa4ba4ecb2b1ecd"},
		},
		{
			path:                   "testdata/results--valid-3",
			expectedErr:            "",
			expectedValidatorCount: 3,
			expectedAggregations:   true,
			expectedNonces:         []uint64{2731, 2732, 2733},
			expectedPubkeys: []string{
				"8c80b0d2ccb54a780996a14892f9f98b2dd09c233c488be381a7719e709433c8ff756ca37134a51df71d58cabe1fd53b",
				"ac5a7fd98f8102588feacb97abf1ecfffef398216ef169e2cff9a710093f81a11734f3b83d1e0c937645bcf3b3dee40c",
				"865d74c82589eb0f3d954af56cc9b5820b1fb371f27d49ed931d7f707f02f3ffb943064a355bc289aa251ff0f7cee28f",
			},
		},
		{
			path:        "testdata/results--missing-aggregations",
			expectedErr: "failed to load aggregated keyshares: open testdata/results--missing-aggregations/keyshares.json: no such file or directory",
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			results, err := OpenResultsDir(test.path)
			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
				return
			}
			require.NoError(t, err)
			require.Equal(t, test.expectedValidatorCount, len(results.Validators))
			require.Equal(t, test.expectedAggregations, results.AggregatedDepositData != nil, "AggregatedDepositData")
			require.Equal(t, test.expectedAggregations, results.AggregatedKeyShares != nil, "AggregatedKeyShares")
			require.Equal(t, test.expectedAggregations, results.AggregatedProofs != nil, "AggregatedProofs")
			for i, v := range results.Validators {
				require.Equal(t, test.expectedNonces[i], v.Nonce)
				require.Equal(t, test.expectedPubkeys[i], v.PublicKey)
				require.NotEmpty(t, v.DepositData)
				require.NotEmpty(t, v.KeyShares)
				require.NotEmpty(t, v.KeyShares.Shares)
				require.NotEmpty(t, v.Proofs)
			}
		})
	}
}

func TestValidateResultsDir(t *testing.T) {
	tests := []struct {
		path            string
		validatorCount  int
		ownerAddress    common.Address
		ownerNonce      uint64
		withdrawAddress common.Address
		expectedErr     string
	}{
		{
			path:            "testdata/results--valid-1",
			validatorCount:  1,
			ownerAddress:    common.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35"),
			ownerNonce:      2731,
			withdrawAddress: common.HexToAddress("0x5cC0DdE14E7256340CC820415a6022a7d1c93A35"),
			expectedErr:     "",
		},
		{
			path:            "testdata/results--valid-3",
			validatorCount:  3,
			ownerAddress:    common.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35"),
			ownerNonce:      2731,
			withdrawAddress: common.HexToAddress("0x5cC0DdE14E7256340CC820415a6022a7d1c93A35"),
			expectedErr:     "",
		},
		{
			path:            "testdata/results--missing-aggregations",
			validatorCount:  3,
			ownerAddress:    common.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35"),
			ownerNonce:      2731,
			withdrawAddress: common.HexToAddress("0x5cC0DdE14E7256340CC820415a6022a7d1c93A35"),
			expectedErr:     "failed to open results directory: failed to load aggregated keyshares: open testdata/results--missing-aggregations/keyshares.json: no such file or directory",
		},
		{
			path:            "testdata/results--incorrect-pubkey",
			validatorCount:  1,
			ownerAddress:    common.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35"),
			ownerNonce:      2731,
			withdrawAddress: common.HexToAddress("0x5cC0DdE14E7256340CC820415a6022a7d1c93A35"),
			expectedErr:     "validator public key does not match deposit-data public key",
		},
		{
			path:            "testdata/results--invalid-deposit-data-signature",
			validatorCount:  1,
			ownerAddress:    common.HexToAddress("0x5cc0dde14e7256340cc820415a6022a7d1c93a35"),
			ownerNonce:      2731,
			withdrawAddress: common.HexToAddress("0x5cC0DdE14E7256340CC820415a6022a7d1c93A35"),
			expectedErr:     "err validating deposit data failed to verify deposit roots: failed to verify deposit data: invalid signature",
		},
	}
	for _, test := range tests {
		t.Run(test.path, func(t *testing.T) {
			err := ValidateResultsDir(test.path, test.validatorCount, test.ownerAddress, test.ownerNonce, test.withdrawAddress)
			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
				return
			}
			require.NoError(t, err)
		})
	}
}
