package integration_test

import (
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestResignValidEOASig(t *testing.T) {
	t.Parallel()
	env := setupEIP1271Test(t, "./stubs", func(_ common.Address) *stubs.Client {
		return &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				return nil, nil
			},
		}
	})
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		rMsg, err := env.clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			eth1Creds(env.withdraw),
			env.owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		depositData, ks, proofs, err := executeResign(t, env.clnt, rMsgs, env.sk)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, env.owner, 10, env.withdraw)
		require.NoError(t, err)
	})
}

func TestResignInvalidEOASig(t *testing.T) {
	t.Parallel()
	ids := []uint64{11, 22, 33, 44}
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	var nonce uint64
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	c, err := initiator.New(ops, zap.L().Named("integration-tests"), testVersion, rootCert, false)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		invalidSignedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/invalid_proofs.json")
		require.NoError(t, err)
		ops, err := initiator.ValidatedOperatorData(ids, c.Operators)
		require.NoError(t, err)
		for i, op := range ops {
			if err := spec.ValidateCeremonyProof(signedProofs[0][0].Proof.ValidatorPubKey, op, *signedProofs[0][i]); err != nil {
				require.NoError(t, err)
			}
		}
		_, err = c.ConstructResignMessage(
			ids,
			invalidSignedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			eth1Creds(withdraw),
			[20]byte{},
			nonce,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			invalidSignedProofs[0])
		require.ErrorContains(t, err, "crypto/rsa: verification error")
	})
}

func TestResignValidContractSig(t *testing.T) {
	t.Parallel()
	env := setupEIP1271Test(t, "./stubs", func(owner common.Address) *stubs.Client {
		return &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.MAGIC_VALUE_ETH_SIGN[:])
				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{
				owner: true,
			},
		}
	})
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		rMsg, err := env.clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			eth1Creds(env.withdraw),
			env.owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		depositData, ks, proofs, err := executeResign(t, env.clnt, rMsgs, env.sk)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, env.owner, 10, env.withdraw)
		require.NoError(t, err)
	})
}

func TestResignInvalidContractSig(t *testing.T) {
	t.Parallel()
	env := setupEIP1271Test(t, "./stubs", func(owner common.Address) *stubs.Client {
		return &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.InvalidSigValue[:])
				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{
				owner: true,
			},
		}
	})
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		rMsg, err := env.clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0][0].Proof.ValidatorPubKey,
			"holesky",
			eth1Creds(env.withdraw),
			env.owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		_, _, _, err = executeResign(t, env.clnt, rMsgs, env.sk)
		require.Error(t, err, "signature invalid")
	})
}
