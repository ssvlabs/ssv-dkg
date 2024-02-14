package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/utils/test_utils"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

func TestHappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.2")
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := test_utils.CreateTestOperator(t, 2, "v1.0.2")
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := test_utils.CreateTestOperator(t, 3, "v1.0.2")
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := test_utils.CreateTestOperator(t, 4, "v1.0.2")
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	srv5 := test_utils.CreateTestOperator(t, 5, "v1.0.2")
	ops[5] = initiator.Operator{Addr: srv5.HttpSrv.URL, ID: 5, PubKey: &srv5.PrivKey.PublicKey}
	srv6 := test_utils.CreateTestOperator(t, 6, "v1.0.2")
	ops[6] = initiator.Operator{Addr: srv6.HttpSrv.URL, ID: 6, PubKey: &srv6.PrivKey.PublicKey}
	srv7 := test_utils.CreateTestOperator(t, 7, "v1.0.2")
	ops[7] = initiator.Operator{Addr: srv7.HttpSrv.URL, ID: 7, PubKey: &srv7.PrivKey.PublicKey}
	srv8 := test_utils.CreateTestOperator(t, 8, "v1.0.2")
	ops[8] = initiator.Operator{Addr: srv8.HttpSrv.URL, ID: 8, PubKey: &srv8.PrivKey.PublicKey}
	srv9 := test_utils.CreateTestOperator(t, 9, "v1.0.2")
	ops[9] = initiator.Operator{Addr: srv9.HttpSrv.URL, ID: 9, PubKey: &srv9.PrivKey.PublicKey}
	srv10 := test_utils.CreateTestOperator(t, 10, "v1.0.2")
	ops[10] = initiator.Operator{Addr: srv10.HttpSrv.URL, ID: 10, PubKey: &srv10.PrivKey.PublicKey}
	srv11 := test_utils.CreateTestOperator(t, 11, "v1.0.2")
	ops[11] = initiator.Operator{Addr: srv11.HttpSrv.URL, ID: 11, PubKey: &srv11.PrivKey.PublicKey}
	srv12 := test_utils.CreateTestOperator(t, 12, "v1.0.2")
	ops[12] = initiator.Operator{Addr: srv12.HttpSrv.URL, ID: 12, PubKey: &srv12.PrivKey.PublicKey}
	srv13 := test_utils.CreateTestOperator(t, 13, "v1.0.2")
	ops[13] = initiator.Operator{Addr: srv13.HttpSrv.URL, ID: 13, PubKey: &srv13.PrivKey.PublicKey}
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	clnt := initiator.New(priv, ops, logger, "v1.0.2")
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	t.Run("test 4 operators happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "holesky", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 7 operators happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 7, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 10 operators happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 10, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey, srv8.PrivKey, srv9.PrivKey, srv10.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 13 operators happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 13, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey, srv8.PrivKey, srv9.PrivKey, srv10.PrivKey, srv11.PrivKey, srv12.PrivKey, srv13.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
	})
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
	srv13.HttpSrv.Close()
}

func TestThreshold(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.2")
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := test_utils.CreateTestOperator(t, 2, "v1.0.2")
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := test_utils.CreateTestOperator(t, 3, "v1.0.2")
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := test_utils.CreateTestOperator(t, 4, "v1.0.2")
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	srv5 := test_utils.CreateTestOperator(t, 5, "v1.0.2")
	ops[5] = initiator.Operator{Addr: srv5.HttpSrv.URL, ID: 5, PubKey: &srv5.PrivKey.PublicKey}
	srv6 := test_utils.CreateTestOperator(t, 6, "v1.0.2")
	ops[6] = initiator.Operator{Addr: srv6.HttpSrv.URL, ID: 6, PubKey: &srv6.PrivKey.PublicKey}
	srv7 := test_utils.CreateTestOperator(t, 7, "v1.0.2")
	ops[7] = initiator.Operator{Addr: srv7.HttpSrv.URL, ID: 7, PubKey: &srv7.PrivKey.PublicKey}
	srv8 := test_utils.CreateTestOperator(t, 8, "v1.0.2")
	ops[8] = initiator.Operator{Addr: srv8.HttpSrv.URL, ID: 8, PubKey: &srv8.PrivKey.PublicKey}
	srv9 := test_utils.CreateTestOperator(t, 9, "v1.0.2")
	ops[9] = initiator.Operator{Addr: srv9.HttpSrv.URL, ID: 9, PubKey: &srv9.PrivKey.PublicKey}
	srv10 := test_utils.CreateTestOperator(t, 10, "v1.0.2")
	ops[10] = initiator.Operator{Addr: srv10.HttpSrv.URL, ID: 10, PubKey: &srv10.PrivKey.PublicKey}
	srv11 := test_utils.CreateTestOperator(t, 11, "v1.0.2")
	ops[11] = initiator.Operator{Addr: srv11.HttpSrv.URL, ID: 11, PubKey: &srv11.PrivKey.PublicKey}
	srv12 := test_utils.CreateTestOperator(t, 12, "v1.0.2")
	ops[12] = initiator.Operator{Addr: srv12.HttpSrv.URL, ID: 12, PubKey: &srv12.PrivKey.PublicKey}
	srv13 := test_utils.CreateTestOperator(t, 13, "v1.0.2")
	ops[13] = initiator.Operator{Addr: srv13.HttpSrv.URL, ID: 13, PubKey: &srv13.PrivKey.PublicKey}
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	clnt := initiator.New(priv, ops, logger, "v1.0.2")
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	t.Run("test 13 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		threshold, err := utils.GetThreshold([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})
		require.NoError(t, err)
		priviteKeys := []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey, srv8.PrivKey}
		require.Less(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 13, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid minimum threshold
		priviteKeys = []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey, srv8.PrivKey, srv9.PrivKey}
		require.Equal(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 13, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 10 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		threshold, err := utils.GetThreshold([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10})
		require.NoError(t, err)
		priviteKeys := []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey}
		require.Less(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 10, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid minimum threshold
		priviteKeys = []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv6.PrivKey, srv7.PrivKey}
		require.Equal(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 10, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 7 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		threshold, err := utils.GetThreshold([]uint64{1, 2, 3, 4, 5, 6, 7})
		require.NoError(t, err)
		priviteKeys := []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}
		require.Less(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 7, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid minimum threshold
		priviteKeys = []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey}
		require.Equal(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 7, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 4 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid threshold
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
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
	srv13.HttpSrv.Close()
}

func TestUnhappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.2")
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := test_utils.CreateTestOperator(t, 2, "v1.0.2")
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := test_utils.CreateTestOperator(t, 3, "v1.0.2")
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := test_utils.CreateTestOperator(t, 4, "v1.0.2")
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	srv5 := test_utils.CreateTestOperator(t, 5, "v1.0.2")
	ops[5] = initiator.Operator{Addr: srv5.HttpSrv.URL, ID: 5, PubKey: &srv5.PrivKey.PublicKey}
	srv6 := test_utils.CreateTestOperator(t, 6, "v1.0.2")
	ops[6] = initiator.Operator{Addr: srv6.HttpSrv.URL, ID: 6, PubKey: &srv6.PrivKey.PublicKey}
	srv7 := test_utils.CreateTestOperator(t, 7, "v1.0.2")
	ops[7] = initiator.Operator{Addr: srv7.HttpSrv.URL, ID: 7, PubKey: &srv7.PrivKey.PublicKey}
	srv8 := test_utils.CreateTestOperator(t, 8, "v1.0.2")
	ops[8] = initiator.Operator{Addr: srv8.HttpSrv.URL, ID: 8, PubKey: &srv8.PrivKey.PublicKey}
	srv9 := test_utils.CreateTestOperator(t, 9, "v1.0.2")
	ops[9] = initiator.Operator{Addr: srv9.HttpSrv.URL, ID: 9, PubKey: &srv9.PrivKey.PublicKey}
	srv10 := test_utils.CreateTestOperator(t, 10, "v1.0.2")
	ops[10] = initiator.Operator{Addr: srv10.HttpSrv.URL, ID: 10, PubKey: &srv10.PrivKey.PublicKey}
	srv11 := test_utils.CreateTestOperator(t, 11, "v1.0.2")
	ops[11] = initiator.Operator{Addr: srv11.HttpSrv.URL, ID: 11, PubKey: &srv11.PrivKey.PublicKey}
	srv12 := test_utils.CreateTestOperator(t, 12, "v1.0.2")
	ops[12] = initiator.Operator{Addr: srv12.HttpSrv.URL, ID: 12, PubKey: &srv12.PrivKey.PublicKey}
	srv13 := test_utils.CreateTestOperator(t, 13, "v1.0.2")
	ops[13] = initiator.Operator{Addr: srv13.HttpSrv.URL, ID: 13, PubKey: &srv13.PrivKey.PublicKey}
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	clnt := initiator.New(priv, ops, logger, "v1.0.2")
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	depositData, ks, ceremeonySigs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
	require.NoError(t, err)
	sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
	require.NoError(t, err)
	pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
	require.NoError(t, err)
	err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
	require.NoError(t, err)
	err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
	require.NoError(t, err)
	marshalledKs, err := json.Marshal(ks)
	require.NoError(t, err)
	cSigs, err := json.Marshal(ceremeonySigs)
	require.NoError(t, err)
	t.Run("test wrong operators shares order at SSV payload", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		_, ks, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		signatureOffset := phase0.SignatureLength
		pubKeysOffset := phase0.PublicKeyLength*13 + signatureOffset
		_ = utils.SplitBytes(sharesDataSigned[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
		encryptedKeys := utils.SplitBytes(sharesDataSigned[pubKeysOffset:], len(sharesDataSigned[pubKeysOffset:])/13)
		wrongOrderSharesData := make([]byte, 0)
		wrongOrderSharesData = append(wrongOrderSharesData, sharesDataSigned[:pubKeysOffset]...)
		for i := len(encryptedKeys) - 1; i >= 0; i-- {
			wrongOrderSharesData = append(wrongOrderSharesData, encryptedKeys[i]...)
		}
		err = testSharesData(ops, 13, []*rsa.PrivateKey{srv13.PrivKey, srv12.PrivKey, srv11.PrivKey, srv10.PrivKey, srv9.PrivKey, srv8.PrivKey, srv7.PrivKey, srv6.PrivKey, srv5.PrivKey, srv4.PrivKey, srv3.PrivKey, srv2.PrivKey, srv1.PrivKey}, wrongOrderSharesData, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "shares order is incorrect")
	})
	t.Run("test same ID", func(t *testing.T) {
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "got init msg for existing instance")
	})
	t.Run("test wrong operator IDs", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{101, 6, 7, 8}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operator is not in given operator data list")
	})
	t.Run("test wrong operator amount 5,6,8,9,11,12", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")

		_, _, err = clnt.StartReshare(crypto.NewID(), []uint64{1, 2, 3}, marshalledKs, cSigs, 1)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		_, _, err = clnt.StartReshare(crypto.NewID(), []uint64{5, 6, 7}, marshalledKs, cSigs, 1)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		_, _, err = clnt.StartReshare(crypto.NewID(), []uint64{5, 6, 7, 8, 9}, marshalledKs, cSigs, 1)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, err = clnt.StartReshare(crypto.NewID(), []uint64{5, 6, 7, 8, 9, 10, 11, 12}, marshalledKs, cSigs, 1)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		_, _, err = clnt.StartReshare(crypto.NewID(), []uint64{5, 6, 7, 8, 9, 10, 11, 12, 13}, marshalledKs, cSigs, 1)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
	})
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
	srv13.HttpSrv.Close()
}

func TestReshareHappyFlow(t *testing.T) {
	err := logging.SetGlobalLogger("debug", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.2")
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := test_utils.CreateTestOperator(t, 2, "v1.0.2")
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := test_utils.CreateTestOperator(t, 3, "v1.0.2")
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := test_utils.CreateTestOperator(t, 4, "v1.0.2")
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	srv5 := test_utils.CreateTestOperator(t, 5, "v1.0.2")
	ops[5] = initiator.Operator{Addr: srv5.HttpSrv.URL, ID: 5, PubKey: &srv5.PrivKey.PublicKey}
	srv6 := test_utils.CreateTestOperator(t, 6, "v1.0.2")
	ops[6] = initiator.Operator{Addr: srv6.HttpSrv.URL, ID: 6, PubKey: &srv6.PrivKey.PublicKey}
	srv7 := test_utils.CreateTestOperator(t, 7, "v1.0.2")
	ops[7] = initiator.Operator{Addr: srv7.HttpSrv.URL, ID: 7, PubKey: &srv7.PrivKey.PublicKey}
	srv8 := test_utils.CreateTestOperator(t, 8, "v1.0.2")
	ops[8] = initiator.Operator{Addr: srv8.HttpSrv.URL, ID: 8, PubKey: &srv8.PrivKey.PublicKey}
	srv9 := test_utils.CreateTestOperator(t, 9, "v1.0.2")
	ops[9] = initiator.Operator{Addr: srv9.HttpSrv.URL, ID: 9, PubKey: &srv9.PrivKey.PublicKey}
	srv10 := test_utils.CreateTestOperator(t, 10, "v1.0.2")
	ops[10] = initiator.Operator{Addr: srv10.HttpSrv.URL, ID: 10, PubKey: &srv10.PrivKey.PublicKey}
	srv11 := test_utils.CreateTestOperator(t, 11, "v1.0.2")
	ops[11] = initiator.Operator{Addr: srv11.HttpSrv.URL, ID: 11, PubKey: &srv11.PrivKey.PublicKey}
	srv12 := test_utils.CreateTestOperator(t, 12, "v1.0.2")
	ops[12] = initiator.Operator{Addr: srv12.HttpSrv.URL, ID: 12, PubKey: &srv12.PrivKey.PublicKey}
	srv13 := test_utils.CreateTestOperator(t, 13, "v1.0.2")
	ops[13] = initiator.Operator{Addr: srv13.HttpSrv.URL, ID: 13, PubKey: &srv13.PrivKey.PublicKey}
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	i := initiator.New(priv, ops, logger, "v1.0.2")
	t.Run("test reshare 4 new disjoint operators", func(t *testing.T) {
		id := crypto.NewID()
		ids := []uint64{1, 2, 3, 4}
		depositData, ks, ceremeonySigs, err := i.StartDKG(id, withdraw.Bytes(), ids, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		newIds := []uint64{5, 6, 7, 8}
		newId := crypto.NewID()
		marshalledKs, err := json.Marshal(ks)
		require.NoError(t, err)
		cSigs, err := json.Marshal(ceremeonySigs)
		require.NoError(t, err)
		ks, _, err = i.StartReshare(newId, newIds, marshalledKs, cSigs, 1)
		require.NoError(t, err)
		sharesDataSigned, err = hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err = hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		// check if threshold holds
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv5.PrivKey, srv6.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv5.PrivKey, srv6.PrivKey, srv7.PrivKey, srv8.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.NoError(t, err)
		// check if old nodes cant decrypt
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.ErrorContains(t, err, "could not decrypt key: crypto/rsa: decryption error")
	})
	t.Run("test reshare 4 joint operators: 1 old + 3 new", func(t *testing.T) {
		id := crypto.NewID()
		ids := []uint64{1, 2, 3, 4}
		depositData, ks, ceremeonySigs, err := i.StartDKG(id, withdraw.Bytes(), ids, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		newIds := []uint64{1, 7, 8, 9}
		newId := crypto.NewID()
		marshalledKs, err := json.Marshal(ks)
		require.NoError(t, err)
		cSigs, err := json.Marshal(ceremeonySigs)
		require.NoError(t, err)
		ks, _, err = i.StartReshare(newId, newIds, marshalledKs, cSigs, 1)
		require.NoError(t, err)
		sharesDataSigned, err = hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err = hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		// check if threshold holds
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv7.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv7.PrivKey, srv8.PrivKey, srv9.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.NoError(t, err)
		// check if old nodes cant decrypt
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.ErrorContains(t, err, "could not decrypt key: crypto/rsa: decryption error")
	})
	t.Run("test reshare 7 joint operators: 4 old + 3 new", func(t *testing.T) {
		id := crypto.NewID()
		ids := []uint64{1, 2, 3, 4}
		depositData, ks, ceremeonySigs, err := i.StartDKG(id, withdraw.Bytes(), ids, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		newIds := []uint64{1, 2, 3, 4, 5, 8, 9}
		newId := crypto.NewID()
		marshalledKs, err := json.Marshal(ks)
		require.NoError(t, err)
		cSigs, err := json.Marshal(ceremeonySigs)
		require.NoError(t, err)
		ks, _, err = i.StartReshare(newId, newIds, marshalledKs, cSigs, 1)
		require.NoError(t, err)
		sharesDataSigned, err = hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err = hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		// check if threshold holds
		err = testSharesData(ops, 7, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		err = testSharesData(ops, 7, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey, srv5.PrivKey, srv8.PrivKey, srv9.PrivKey}, sharesDataSigned, pubkeyraw, owner, 1)
		require.NoError(t, err)
	})
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
	srv13.HttpSrv.Close()
}

func TestWrongInitiatorVersion(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.2")
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := test_utils.CreateTestOperator(t, 2, "v1.0.2")
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := test_utils.CreateTestOperator(t, 3, "v1.0.2")
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := test_utils.CreateTestOperator(t, 4, "v1.0.2")
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	clnt := initiator.New(priv, ops, logger, "v1.0.0")
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
	require.ErrorContains(t, err, "wrong version")
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func TestWrongOperatorVersion(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.0")
	ops[1] = initiator.Operator{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}
	srv2 := test_utils.CreateTestOperator(t, 2, "v1.0.2")
	ops[2] = initiator.Operator{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey}
	srv3 := test_utils.CreateTestOperator(t, 3, "v1.0.2")
	ops[3] = initiator.Operator{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey}
	srv4 := test_utils.CreateTestOperator(t, 4, "v1.0.2")
	ops[4] = initiator.Operator{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey}
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	clnt := initiator.New(priv, ops, logger, "v1.0.2")
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
	require.ErrorContains(t, err, "wrong version")
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func testSharesData(ops map[uint64]initiator.Operator, operatorCount int, keys []*rsa.PrivateKey, sharesData, validatorPublicKey []byte, owner common.Address, nonce uint16) error {
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("shares data len is not correct")
	}
	signature := sharesData[:signatureOffset]
	msg := []byte("Hello")
	err := crypto.VerifyOwnerNonceSignature(signature, owner, validatorPublicKey, nonce)
	if err != nil {
		return err
	}
	_ = utils.SplitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := utils.SplitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	sigs2 := make(map[uint64][]byte)
	opsIDs := make([]uint64, 0)
	for i, enck := range encryptedKeys {
		var priv *rsa.PrivateKey
		if utils.Contains(keys, i) {
			priv = keys[i]
		} else {
			continue
		}
		share, err := rsaencryption.DecodeKey(priv, enck)
		if err != nil {
			return err
		}
		secret := &bls.SecretKey{}
		err = secret.SetHexString(string(share))
		if err != nil {
			return err
		}
		// Find operator ID by PubKey
		var operatorID uint64
		for id, op := range ops {
			if bytes.Equal(priv.PublicKey.N.Bytes(), op.PubKey.N.Bytes()) {
				operatorID = id
				break
			}
		}
		sig := secret.SignByte(msg)
		sigs2[operatorID] = sig.Serialize()

		// operators encoded shares should be ordered in increasing manner
		for _, op := range ops {
			if op.PubKey == &priv.PublicKey {
				opsIDs = append(opsIDs, op.ID)
			}
		}
	}
	// check if operators ordered correctly
	k := uint64(0)
	for _, i := range opsIDs {
		if i > k {
			k = i
		} else {
			return fmt.Errorf("shares order is incorrect")
		}
	}
	recon, err := ReconstructSignatures(sigs2)
	if err != nil {
		return err
	}
	err = VerifyReconstructedSignature(recon, validatorPublicKey, msg)
	if err != nil {
		return err
	}
	return nil
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

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey, msg []byte) error {
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
