package integration_test

import (
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestReshareValidEOASig(t *testing.T) {
	t.Parallel()
	env := setupEIP1271Test(t, "../examples/initiator", func(_ common.Address) *stubs.Client {
		return &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				return nil, nil
			},
		}
	})
	signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		rMsg, err := env.clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", env.withdraw[:], env.owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ReshareMessage{rMsg}
		depositData, ks, proofs, err := executeReshare(t, env.clnt, rMsgs, env.sk)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, env.owner, 0, env.withdraw)
		require.NoError(t, err)
	})
}

func TestReshareInvalidEOASig(t *testing.T) {
	t.Parallel()
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/invalid_proofs.json")
	require.NoError(t, err)
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
	clnt, err := initiator.New(ops, zap.L().Named("integration-tests"), testVersion, rootCert, false)
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		_, err := clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", withdraw[:], [20]byte{0}, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs[0])
		require.Error(t, err, "invalid owner address")
	})
}

func TestReshareValidContractSig(t *testing.T) {
	t.Parallel()
	env := setupEIP1271Test(t, "../examples/initiator", func(owner common.Address) *stubs.Client {
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
	signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		rMsg, err := env.clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", env.withdraw[:], env.owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ReshareMessage{rMsg}
		depositData, ks, proofs, err := executeReshare(t, env.clnt, rMsgs, env.sk)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, env.owner, 0, env.withdraw)
		require.NoError(t, err)
	})
}

func TestReshareInvalidContractSig(t *testing.T) {
	t.Parallel()
	env := setupEIP1271Test(t, "../examples/initiator", func(owner common.Address) *stubs.Client {
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
	signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		rMsg, err := env.clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", env.withdraw[:], env.owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ReshareMessage{rMsg}
		_, _, _, err = executeReshare(t, env.clnt, rMsgs, env.sk)
		require.Error(t, err, "signature invalid")
	})
}
