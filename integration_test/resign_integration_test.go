package integration_test

import (
	"testing"

	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestInitResignHappyFlows(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	clnt, err := initiator.New(env.ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	sk, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PublicKey)
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
			id := spec.NewID()
			depositData, ks, proofs, err := clnt.StartDKG(id, eth1Creds(withdraw), tc.opIDs, "holesky", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
			require.NoError(t, err)
			err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
			require.NoError(t, err)
			signedProofs := toSpecSignedProofs(proofs)
			rMsg, err := clnt.ConstructResignMessage(
				tc.opIDs, signedProofs[0].Proof.ValidatorPubKey, "mainnet",
				eth1Creds(withdraw), owner, 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs,
			)
			require.NoError(t, err)
			rMsgs := []*wire.ResignMessage{rMsg}
			depositDataArr, ksArr, proofsArr, err := executeResign(t, clnt, rMsgs, sk)
			require.NoError(t, err)
			err = validator.ValidateResults(depositDataArr, ksArr[0], proofsArr, 1, owner, 10, withdraw)
			require.NoError(t, err)
		})
	}
}

func TestInitResignChangeOwnerHappyFlows(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	clnt, err := initiator.New(env.ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	sk, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PublicKey)
	skNewOwner, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	newOwner := eth_crypto.PubkeyToAddress(skNewOwner.PublicKey)
	t.Run("4 operators change owner", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44}, "holesky", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		signedProofs := toSpecSignedProofs(proofs)
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44}, signedProofs[0].Proof.ValidatorPubKey, "mainnet",
			eth1Creds(withdraw), newOwner, 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs,
		)
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		depositDataArr, ksArr, proofsArr, err := executeResign(t, clnt, rMsgs, sk)
		require.NoError(t, err)
		err = validator.ValidateResults(depositDataArr, ksArr[0], proofsArr, 1, newOwner, 10, withdraw)
		require.NoError(t, err)
	})
}
