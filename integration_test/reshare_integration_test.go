package integration_test

import (
	"testing"

	"github.com/stretchr/testify/require"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestReshareHappyFlows(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		newIDs []uint64
	}{
		{"4 operators", []uint64{55, 66, 77, 88}},
		{"7 operators", []uint64{11, 22, 33, 44, 55, 66, 77}},
		{"10 operators", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110}},
		{"13 operators", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			env := setupFixtureTest(t)

			// init with 4 operators
			clnt, err := initiator.New(env.ops.Clone(), env.logger, testVersion, rootCert, false)
			require.NoError(t, err)
			id := spec.NewID()
			depositData, ks, proofs, err := clnt.StartDKG(id, env.withdraw.Bytes(), []uint64{11, 22, 33, 44}, "holesky", env.owner, 1, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
			require.NoError(t, err)
			err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, env.owner, 1, env.withdraw)
			require.NoError(t, err)

			// reshare to new operators
			signedProofs := toSpecSignedProofs(proofs)
			clnt, err = initiator.New(env.ops.Clone(), env.logger, testVersion, rootCert, false)
			require.NoError(t, err)
			rMsg, err := clnt.ConstructReshareMessage(
				[]uint64{11, 22, 33, 44}, tc.newIDs,
				signedProofs[0].Proof.ValidatorPubKey, "holesky", env.withdraw.Bytes(),
				env.owner, 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs,
			)
			require.NoError(t, err)
			rMsgs := []*wire.ReshareMessage{rMsg}
			reshareDepositData, reshareKs, reshareProofs, err := executeReshare(t, clnt, rMsgs, env.sk)
			require.NoError(t, err)
			err = validator.ValidateResults(reshareDepositData, reshareKs[0], reshareProofs, 1, env.owner, 10, env.withdraw)
			require.NoError(t, err)
		})
	}
}

// toSpecSignedProofs converts wire.SignedProof to spec.SignedProof for use with ConstructReshareMessage/ConstructResignMessage.
func toSpecSignedProofs(proofs []*wire.SignedProof) []*spec.SignedProof {
	signedProofs := make([]*spec.SignedProof, len(proofs))
	for i, p := range proofs {
		signedProofs[i] = &p.SignedProof
	}
	return signedProofs
}
