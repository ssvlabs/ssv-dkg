package integration_test

import (
	"encoding/hex"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
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
	clnt, err := initiator.New(ops, logger, version, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	sk, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PublicKey)
	t.Run("test 4 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "holesky", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
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
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs,
		)
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		depositDataArr, ksArr, proofsArr, err := clnt.StartResigning(id, &signedResign)
		require.NoError(t, err)
		err = validator.ValidateResults(depositDataArr, ksArr[0], proofsArr, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 7 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77}, "holesky", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
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
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77},
			signedProofs[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs,
		)
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		depositDataArr, ksArr, proofsArr, err := clnt.StartResigning(id, &signedResign)
		require.NoError(t, err)
		err = validator.ValidateResults(depositDataArr, ksArr[0], proofsArr, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 10 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, "holesky", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
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
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100},
			signedProofs[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs,
		)
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		depositDataArr, ksArr, proofsArr, err := clnt.StartResigning(id, &signedResign)
		require.NoError(t, err)
		err = validator.ValidateResults(depositDataArr, ksArr[0], proofsArr, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 13 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "holesky", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		signedProofs := []*spec.SignedProof{}
		for _, p := range proofs {
			signedProofs = append(signedProofs, &p.SignedProof)
		}
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133},
			signedProofs[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs,
		)
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		depositDataArr, ksArr, proofsArr, err := clnt.StartResigning(id, &signedResign)
		require.NoError(t, err)
		err = validator.ValidateResults(depositDataArr, ksArr[0], proofsArr, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
