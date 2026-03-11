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

func TestBulkResignHappyFlows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		dir    string
		opIDs  []uint64
		amount uint64
	}{
		{
			name:   "4 operators",
			dir:    "4",
			opIDs:  []uint64{11, 22, 33, 44},
			amount: uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:   "7 operators",
			dir:    "7",
			opIDs:  []uint64{11, 22, 33, 44, 55, 66, 77},
			amount: uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:   "10 operators",
			dir:    "10",
			opIDs:  []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110},
			amount: uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		{
			name:   "13 operators",
			dir:    "13",
			opIDs:  []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113},
			amount: 2048000000000,
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
			for i, c := range initCeremonies {
				err = validator.ValidateResultsDir(baseDir+"/"+c.Name(), validators[i], env.owner, 1, env.withdraw)
				require.NoError(t, err)
			}

			for i, c := range initCeremonies {
				signedProofs := loadCeremonyProofs(t, baseDir, c.Name(), validators[i])

				clnt, err := initiator.New(env.ops.Clone(), env.logger, testVersion, rootCert, false)
				require.NoError(t, err)
				rMsg, err := clnt.ConstructResignMessage(
					tc.opIDs,
					signedProofs[0][0].Proof.ValidatorPubKey, "mainnet", env.withdraw.Bytes(),
					env.owner, 10, tc.amount, signedProofs[0],
				)
				require.NoError(t, err)
				rMsgs := []*wire.ResignMessage{rMsg}
				resignDepositData, resignKs, resignProofs, err := executeResign(t, clnt, rMsgs, env.sk)
				require.NoError(t, err)
				err = validator.ValidateResults(resignDepositData, resignKs[0], resignProofs, 1, env.owner, 10, env.withdraw)
				require.NoError(t, err)
			}
		})
	}
}
