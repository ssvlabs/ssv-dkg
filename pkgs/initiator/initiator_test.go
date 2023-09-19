package initiator_test

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/go-chi/chi/v5"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	ourcrypto "github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/load"
	operator "github.com/bloxapp/ssv-dkg/pkgs/operator"
)

const encryptedKeyLength = 256

// TODO: use mocks instead of servers
type testOperator struct {
	id      uint64
	privKey *rsa.PrivateKey
	srv     *httptest.Server
}

const exmaplePath = "../../examples/"

func TestOperatorMisbehave(t *testing.T) {
	ops := make(map[uint64]initiator.Operator)
	srv1 := CreateTestOperator(t, 1)
	srv2 := CreateTestOperator(t, 2)
	srv3 := CreateTestOperator(t, 3)
	srv4 := CreateTestOperator(t, 4)
	ops[1] = initiator.Operator{srv1.srv.URL, 1, &srv1.privKey.PublicKey}
	ops[2] = initiator.Operator{srv2.srv.URL, 2, &srv2.privKey.PublicKey}
	ops[3] = initiator.Operator{srv3.srv.URL, 3, &srv3.privKey.PublicKey}
	ops[4] = initiator.Operator{srv4.srv.URL, 4, &srv4.privKey.PublicKey}
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
	owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
	t.Run("happy flow", func(t *testing.T) {
		initiator := initiator.New(priv, ops)
		depositData, keyshares, err := initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
		testSharesData(t, ops, []*rsa.PrivateKey{srv1.privKey, srv2.privKey, srv3.privKey, srv4.privKey}, keyshares, owner, 0)
		testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
	})
	t.Run("test wrong amount of opeators < 4", func(t *testing.T) {
		initiator := initiator.New(priv, ops)
		_, _, err = initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "minimum supported amount of operators is 4")
	})
	t.Run("test wrong amount of opeators > 13", func(t *testing.T) {
		initiator := initiator.New(priv, ops)
		_, _, err = initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "maximum supported amount of operators is 13")
	})
	t.Run("test opeators not unique", func(t *testing.T) {
		initiator := initiator.New(priv, ops)
		_, _, err = initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 7, 9, 10, 11, 12, 12}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "operators ids should be unique in the list")
	})

	srv1.srv.Close()
	srv2.srv.Close()
	srv3.srv.Close()
	srv4.srv.Close()
}

func CreateTestOperator(t *testing.T, id uint64) *testOperator {
	priv, err := load.EncryptedPrivateKey(exmaplePath+"operator"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	r := chi.NewRouter()
	swtch := &operator.Switch{
		Logger:           logrus.NewEntry(logrus.New()),
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[operator.InstanceID]time.Time, operator.MaxInstances),
		Instances:        make(map[operator.InstanceID]operator.Instance, operator.MaxInstances),
		PrivateKey:       priv,
	}

	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &operator.Server{
		Logger: logrus.NewEntry(lg).WithField("comp", "server"),
		Router: r,
		State:  swtch,
	}
	operator.RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &testOperator{
		id:      id,
		privKey: priv,
		srv:     sTest,
	}
}

func testSharesData(t *testing.T, ops map[uint64]initiator.Operator, keys []*rsa.PrivateKey, ks *initiator.KeyShares, owner common.Address, nonce uint16) {
	sharesData, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
	require.NoError(t, err)
	validatorPublicKey, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
	require.NoError(t, err)

	operatorCount := len(keys)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := encryptedKeyLength*operatorCount + pubKeysOffset
	require.Len(t, sharesData, sharesExpectedLength)
	signature := sharesData[:signatureOffset]
	msg := []byte("Hello")
	require.NoError(t, ourcrypto.VerifyOwnerNoceSignature(signature, owner, validatorPublicKey, nonce))
	_ = splitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := splitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	sigs2 := make(map[uint64][]byte)
	for i, enck := range encryptedKeys {
		priv := keys[i]
		share, err := rsaencryption.DecodeKey(priv, enck)
		require.NoError(t, err)
		secret := &bls.SecretKey{}
		require.NoError(t, secret.SetHexString(string(share)))
		// Find operator ID by PubKey
		var operatorID uint64
		for id, op := range ops {
			if bytes.Equal(priv.PublicKey.N.Bytes(), op.PubKey.N.Bytes()) {
				operatorID = id
			}
		}
		sig := secret.SignByte(msg)
		sigs2[operatorID] = sig.Serialize()
	}
	recon, err := ReconstructSignatures(sigs2)
	require.NoError(t, err)
	require.NoError(t, VerifyReconstructedSignature(recon, validatorPublicKey, msg))
}

// ReconstructSignatures receives a map of user indexes and serialized bls.Sign.
// It then reconstructs the original threshold signature using lagrange interpolation
func ReconstructSignatures(signatures map[uint64][]byte) (*bls.Sign, error) {
	reconstructedSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for index, signature := range signatures {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", index))
		if err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		blsSig := bls.Sign{}

		err = blsSig.Deserialize(signature)
		if err != nil {
			return nil, err
		}
		sigVec = append(sigVec, blsSig)
	}
	err := reconstructedSig.Recover(sigVec, idVec)
	return &reconstructedSig, err
}

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey []byte, msg []byte) error {
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(validatorPubKey); err != nil {
		return errors.Wrap(err, "could not deserialize validator pk")
	}
	// verify reconstructed sig
	if res := sig.VerifyByte(pk, msg); !res {
		return errors.New("could not reconstruct a valid signature")
	}
	return nil
}

func splitBytes(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func testDepositData(t *testing.T, depsitDataJson *initiator.DepositDataJson, withdrawCred []byte, owner common.Address, nonce uint16) {
	require.True(t, bytes.Equal(ourcrypto.WithdrawalCredentialsHash(withdrawCred), hexutil.MustDecode("0x"+depsitDataJson.WithdrawalCredentials)))
	masterSig := &bls.Sign{}
	require.NoError(t, masterSig.DeserializeHexStr(depsitDataJson.Signature))
	valdatorPubKey := &bls.PublicKey{}
	require.NoError(t, valdatorPubKey.DeserializeHexStr(depsitDataJson.PubKey))

	// Check root
	var fork [4]byte
	copy(fork[:], hexutil.MustDecode("0x"+depsitDataJson.ForkVersion))
	depositDataRoot, err := ourcrypto.DepositDataRoot(withdrawCred, valdatorPubKey, dkg.GetNetworkByFork(fork), initiator.MaxEffectiveBalanceInGwei)
	require.NoError(t, err)
	res := masterSig.VerifyByte(valdatorPubKey, depositDataRoot[:])
	require.True(t, res)
	depositData, _, err := ourcrypto.DepositData(masterSig.Serialize(), withdrawCred, valdatorPubKey.Serialize(), dkg.GetNetworkByFork(fork), initiator.MaxEffectiveBalanceInGwei)
	require.NoError(t, err)
	res, err = ourcrypto.VerifyDepositData(depositData, dkg.GetNetworkByFork(fork))
	require.NoError(t, err)
	require.True(t, res)
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                initiator.MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, _ := depositMsg.HashTreeRoot()
	require.True(t, bytes.Equal(depositMsgRoot[:], hexutil.MustDecode("0x"+depsitDataJson.DepositMessageRoot)))
}
