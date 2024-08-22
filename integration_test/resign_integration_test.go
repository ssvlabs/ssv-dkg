package integration_test

import (
	"testing"

	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
)

func TestInitResignHappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperators(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	sk, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PublicKey)
	t.Run("test 4 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		require.NoError(t, err)
		signedProofs := []*spec.SignedProof{}
		for _, p := range proofs {
			signedProofs = append(signedProofs, &spec.SignedProof{
				Proof: &spec.Proof{
					ValidatorPubKey: p.Proof.ValidatorPubKey,
					EncryptedShare:  p.Proof.EncryptedShare,
					SharePubKey:     p.Proof.SharePubKey,
					Owner:           p.Proof.Owner,
				},
				Signature: p.Signature,
			})
		}
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs, sk, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 7 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		require.NoError(t, err)
		signedProofs := []*spec.SignedProof{}
		for _, p := range proofs {
			signedProofs = append(signedProofs, &p.SignedProof)
		}
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44, 55, 66, 77}, signedProofs, sk, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 10 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		signedProofs := []*spec.SignedProof{}
		for _, p := range proofs {
			signedProofs = append(signedProofs, &p.SignedProof)
		}
		require.NoError(t, err)
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, signedProofs, sk, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 13 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		signedProofs := []*spec.SignedProof{}
		for _, p := range proofs {
			signedProofs = append(signedProofs, &p.SignedProof)
		}
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, signedProofs, sk, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
