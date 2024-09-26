package integration_test

import (
	"bytes"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
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
		originalProofs := proofs
		// sort.Slice(originalProofs, func(i, j int) bool {
		// 	return bytes.Compare(proofs[i].Proof.EncryptedShare, proofs[j].Proof.EncryptedShare) < 0
		// })
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs, sk, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		// sort.Slice(proofs, func(i, j int) bool {
		// 	return bytes.Compare(proofs[i].Proof.EncryptedShare, proofs[j].Proof.EncryptedShare) < 0
		// })
		require.True(t, CompareProofSlices(originalProofs, proofs))
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

// CompareProofSlices compares two slices of *wire.SignedProof for equality.
// Returns true if they are equal, false otherwise.
func CompareProofSlices(a, b []*wire.SignedProof) bool {
	// Check if lengths are equal
	if len(a) != len(b) {
		return false
	}

	// Iterate and compare each proof
	for i := range a {
		if !CompareProofs(a[i].Proof, b[i].Proof) {
			return false
		}
	}
	return true
}

// CompareProofs compares two Proof structs for equality.
func CompareProofs(p1, p2 *spec.Proof) bool {
	// Compare ValidatorPubKey
	if !bytes.Equal(p1.ValidatorPubKey, p2.ValidatorPubKey) {
		return false
	}

	// Compare EncryptedShare
	if !bytes.Equal(p1.EncryptedShare, p2.EncryptedShare) {
		return false
	}

	// Compare SharePubKey
	if !bytes.Equal(p1.SharePubKey, p2.SharePubKey) {
		return false
	}

	// Compare Owner ([20]byte array)
	if p1.Owner != p2.Owner {
		return false
	}

	return true
}
