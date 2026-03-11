package integration_test

import (
	"os"
	"testing"

	"github.com/stretchr/testify/require"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestReshareThresholdOldValidators(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		dir         string
		closedCount int
		oldIDs      []uint64
		newIDs      []uint64
		amount      uint64
	}{
		{
			name:        "4 operators, 1 off, threshold 3",
			dir:         "4",
			closedCount: 1,
			oldIDs:      []uint64{11, 22, 33, 44},
			newIDs:      []uint64{55, 66, 77, 88},
			amount:      uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:        "7 operators, 2 off, threshold 5",
			dir:         "7",
			closedCount: 2,
			oldIDs:      []uint64{11, 22, 33, 44, 55, 66, 77},
			newIDs:      []uint64{44, 55, 66, 77, 88, 99, 110},
			amount:      uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:        "10 operators, 3 off, threshold 7",
			dir:         "10",
			closedCount: 3,
			oldIDs:      []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110},
			newIDs:      []uint64{77, 88, 99, 110, 111, 112, 113},
			amount:      uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:        "13 operators, 4 off, threshold 9",
			dir:         "13",
			closedCount: 4,
			oldIDs:      []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113},
			newIDs:      []uint64{77, 88, 99, 110, 111, 112, 113},
			amount:      2048000000000,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := setupFixtureTest(t)
			baseDir := "./stubs/bulk/" + tc.dir

			// validate existing fixtures
			ceremonies, err := os.ReadDir(baseDir)
			require.NoError(t, err)
			valCounts := []int{1, 10, 100}
			for i, c := range ceremonies {
				err = validator.ValidateResultsDir(baseDir+"/"+c.Name(), valCounts[i], env.owner, 1, env.withdraw)
				require.NoError(t, err)
			}

			// close old operators below threshold
			for i := 0; i < tc.closedCount; i++ {
				env.servers[i].HttpSrv.Close()
			}

			// reshare only single-validator ceremonies
			for i, c := range ceremonies {
				if valCounts[i] != 1 {
					continue
				}
				signedProofs := loadCeremonyProofs(t, baseDir, c.Name(), valCounts[i])

				clnt, err := initiator.New(env.ops.Clone(), env.logger, testVersion, rootCert, false)
				require.NoError(t, err)
				rMsg, err := clnt.ConstructReshareMessage(
					tc.oldIDs, tc.newIDs,
					signedProofs[0][0].Proof.ValidatorPubKey, "mainnet", env.withdraw.Bytes(),
					env.owner, 10, tc.amount, signedProofs[0],
				)
				require.NoError(t, err)
				rMsgs := []*wire.ReshareMessage{rMsg}
				reshareDepositData, reshareKs, reshareProofs, err := executeReshare(t, clnt, rMsgs, env.sk)
				require.NoError(t, err)
				err = validator.ValidateResults(reshareDepositData, reshareKs[0], reshareProofs, 1, env.owner, 10, env.withdraw)
				require.NoError(t, err)
			}
		})
	}
}
