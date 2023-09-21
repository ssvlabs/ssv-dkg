package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	ourcrypto "github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/operator"
)

const encryptedKeyLength = 256
const examplePath = "../examples/"

func TestHappyFlow(t *testing.T) {
	if err := logging.SetGlobalLogger("info", "capital", "console", ""); err != nil {
		panic(err)
	}
	logger := zap.L().Named("integration-tests")
	t.Run("test 4 operators happy flow", func(t *testing.T) {
		ops := make(map[uint64]initiator.Operator)
		srv1 := operator.CreateTestOperator(t, 1)
		ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
		srv2 := operator.CreateTestOperator(t, 2)
		ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
		srv3 := operator.CreateTestOperator(t, 3)
		ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
		srv4 := operator.CreateTestOperator(t, 4)
		ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
		// Initiator priv key
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		clnt := initiator.New(priv, ops, logger)
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := clnt.NewID()
		depositData, ks, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
		require.NoError(t, err)
		testSharesData(t, ops, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
		srv1.HttpSrv.Close()
		srv2.HttpSrv.Close()
		srv3.HttpSrv.Close()
		srv4.HttpSrv.Close()
	})
	t.Run("test 7 operators happy flow", func(t *testing.T) {
		ops := make(map[uint64]initiator.Operator)
		srv1 := operator.CreateTestOperator(t, 1)
		ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
		srv2 := operator.CreateTestOperator(t, 2)
		ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
		srv3 := operator.CreateTestOperator(t, 3)
		ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
		srv4 := operator.CreateTestOperator(t, 4)
		ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
		srv5 := operator.CreateTestOperator(t, 5)
		ops[5] = initiator.Operator{Addr: srv5.HttpSrv.URL, ID: 5, PubKey: &srv5.PrivKey.PublicKey}
		srv6 := operator.CreateTestOperator(t, 6)
		ops[6] = initiator.Operator{Addr: srv6.HttpSrv.URL, ID: 6, PubKey: &srv6.PrivKey.PublicKey}
		srv7 := operator.CreateTestOperator(t, 7)
		ops[7] = initiator.Operator{Addr: srv7.HttpSrv.URL, ID: 7, PubKey: &srv7.PrivKey.PublicKey}
		// Initiator priv key
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		clnt := initiator.New(priv, ops, logger)
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := clnt.NewID()
		depositData, ks, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
		require.NoError(t, err)
		testSharesData(t, ops, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
		srv1.HttpSrv.Close()
		srv2.HttpSrv.Close()
		srv3.HttpSrv.Close()
		srv4.HttpSrv.Close()
		srv5.HttpSrv.Close()
		srv6.HttpSrv.Close()
		srv7.HttpSrv.Close()
	})
	t.Run("test 12 operators happy flow", func(t *testing.T) {
		ops := make(map[uint64]initiator.Operator)
		srv1 := operator.CreateTestOperator(t, 1)
		ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
		srv2 := operator.CreateTestOperator(t, 2)
		ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
		srv3 := operator.CreateTestOperator(t, 3)
		ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
		srv4 := operator.CreateTestOperator(t, 4)
		ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
		srv5 := operator.CreateTestOperator(t, 5)
		ops[5] = initiator.Operator{Addr: srv5.HttpSrv.URL, ID: 5, PubKey: &srv5.PrivKey.PublicKey}
		srv6 := operator.CreateTestOperator(t, 6)
		ops[6] = initiator.Operator{Addr: srv6.HttpSrv.URL, ID: 6, PubKey: &srv6.PrivKey.PublicKey}
		srv7 := operator.CreateTestOperator(t, 7)
		ops[7] = initiator.Operator{Addr: srv7.HttpSrv.URL, ID: 7, PubKey: &srv7.PrivKey.PublicKey}
		srv8 := operator.CreateTestOperator(t, 8)
		ops[8] = initiator.Operator{Addr: srv8.HttpSrv.URL, ID: 8, PubKey: &srv8.PrivKey.PublicKey}
		srv9 := operator.CreateTestOperator(t, 9)
		ops[9] = initiator.Operator{Addr: srv9.HttpSrv.URL, ID: 9, PubKey: &srv9.PrivKey.PublicKey}
		srv10 := operator.CreateTestOperator(t, 10)
		ops[10] = initiator.Operator{Addr: srv10.HttpSrv.URL, ID: 10, PubKey: &srv10.PrivKey.PublicKey}
		srv11 := operator.CreateTestOperator(t, 11)
		ops[11] = initiator.Operator{Addr: srv11.HttpSrv.URL, ID: 11, PubKey: &srv11.PrivKey.PublicKey}
		srv12 := operator.CreateTestOperator(t, 12)
		ops[12] = initiator.Operator{Addr: srv12.HttpSrv.URL, ID: 12, PubKey: &srv12.PrivKey.PublicKey}
		// Initiator priv key
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		clnt := initiator.New(priv, ops, logger)
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := clnt.NewID()
		depositData, ks, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
		require.NoError(t, err)
		testSharesData(t, ops, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey, srv8.PrivKey, srv9.PrivKey, srv10.PrivKey, srv11.PrivKey, srv12.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
		srv1.HttpSrv.Close()
		srv2.HttpSrv.Close()
		srv3.HttpSrv.Close()
		srv4.HttpSrv.Close()
		srv5.HttpSrv.Close()
		srv6.HttpSrv.Close()
		srv7.HttpSrv.Close()
		srv8.HttpSrv.Close()
		srv9.HttpSrv.Close()
		srv10.HttpSrv.Close()
		srv11.HttpSrv.Close()
		srv12.HttpSrv.Close()
	})
}

func TestUnhappyFlow(t *testing.T) {
	if err := logging.SetGlobalLogger("debug", "capital", "console", ""); err != nil {
		panic(err)
	}
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := operator.CreateTestOperatorFromFile(t, 1, examplePath)
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := operator.CreateTestOperatorFromFile(t, 2, examplePath)
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := operator.CreateTestOperatorFromFile(t, 3, examplePath)
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := operator.CreateTestOperatorFromFile(t, 4, examplePath)
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	t.Run("test same ID", func(t *testing.T) {
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		clnt := initiator.New(priv, ops, logger)
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := clnt.NewID()
		depositData, ks, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
		require.NoError(t, err)
		testSharesData(t, ops, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
		_, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "got init msg for existing instance")
		// start a new dkg process and check if we are fine after getting the error
		id = clnt.NewID()
		_, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
	})
	t.Run("test wrong operator IDs", func(t *testing.T) {
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		clnt := initiator.New(priv, ops, logger)
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := clnt.NewID()
		_, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{5, 6, 7, 8}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "operator is not in the list")
		// start a new dkg process and check if we are fine after getting the error
		id = clnt.NewID()
		_, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
	})
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func testSharesData(t *testing.T, ops map[uint64]initiator.Operator, keys []*rsa.PrivateKey, sharesData []byte, validatorPublicKey []byte, owner common.Address, nonce uint16) {
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

func newEthAddress(t *testing.T) common.Address {
	privateKey, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	address := eth_crypto.PubkeyToAddress(*publicKeyECDSA)
	return address
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
