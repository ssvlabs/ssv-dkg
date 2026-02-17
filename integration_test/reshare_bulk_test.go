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

func TestBulkReshareHappyFlows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		dir       string
		oldIDs    []uint64
		newIDs    []uint64
		amount    uint64
		skipLarge bool
	}{
		{
			name:   "4 operators",
			dir:    "4",
			oldIDs: []uint64{11, 22, 33, 44},
			newIDs: []uint64{55, 66, 77, 88},
			amount: uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:      "7 operators",
			dir:       "7",
			oldIDs:    []uint64{11, 22, 33, 44, 55, 66, 77},
			newIDs:    []uint64{77, 88, 99, 110, 111, 112, 113},
			amount:    uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			skipLarge: true,
		},
		{
			name:      "10 operators",
			dir:       "10",
			oldIDs:    []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110},
			newIDs:    []uint64{11, 22, 33, 44},
			amount:    uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			skipLarge: true,
		},
		{
			name:      "13 operators",
			dir:       "13",
			oldIDs:    []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113},
			newIDs:    []uint64{11, 22, 33, 44},
			amount:    2048000000000,
			skipLarge: true,
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := setupFixtureTest(t)
			baseDir := "./stubs/bulk/" + tc.dir

			initCeremonies, err := os.ReadDir(baseDir)
			require.NoError(t, err)
			validators := []int{1, 10, 100}
			require.Len(t, initCeremonies, len(validators))
			for i, c := range initCeremonies {
				err = validator.ValidateResultsDir(baseDir+"/"+c.Name(), validators[i], env.owner, 1, env.withdraw)
				require.NoError(t, err)
			}

			for i, c := range initCeremonies {
				if tc.skipLarge && validators[i] == 100 {
					continue
				}
				signedProofs := loadCeremonyProofs(t, baseDir, c.Name(), validators[i]) //nolint:gosec // validators and initCeremonies have matching lengths
				require.NotEmpty(t, signedProofs)
				require.NotEmpty(t, signedProofs[0])

				clnt, err := initiator.New(env.ops.Clone(), env.logger, testVersion, rootCert, false)
				require.NoError(t, err)
				rMsg, err := clnt.ConstructReshareMessage(
					tc.oldIDs, tc.newIDs,
					signedProofs[0][0].Proof.ValidatorPubKey, "mainnet", eth1Creds(env.withdraw),
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
