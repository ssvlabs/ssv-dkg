package test_utils

import (
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/go-chi/chi/v5"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/operator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

type TestOperator struct {
	ID      uint64
	PrivKey *rsa.PrivateKey
	HttpSrv *httptest.Server
	Srv     *operator.Server
}

func CreateTestOperatorFromFile(t *testing.T, id uint64, examplePath, version, operatorCert, operatorKey string) *TestOperator {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("operator-tests")
	privKey, err := os.ReadFile(filepath.Clean(examplePath + "operator" + fmt.Sprintf("%v", id) + "/encrypted_private_key.json"))
	if err != nil {
		logger.Fatal("failed to read file", zap.Error(err))
		return nil
	}
	priv, err := crypto.DecryptRSAKeystore(privKey, "12345678")
	require.NoError(t, err)
	r := chi.NewRouter()
	operatorPubKey := priv.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodeRSAPublicKey(operatorPubKey)
	require.NoError(t, err)
	swtch := operator.NewSwitch(priv, logger, []byte(version), pkBytes, id)
	tempDir, err := os.MkdirTemp("", "dkg")
	require.NoError(t, err)
	s := &operator.Server{
		Logger:     logger,
		Router:     r,
		State:      swtch,
		OutputPath: tempDir,
	}
	operator.RegisterRoutes(s)
	sTest, err := NewLocalHTTPSTestServer(s.Router, operatorCert, operatorKey)
	require.NoError(t, err)
	return &TestOperator{
		ID:      id,
		PrivKey: priv,
		HttpSrv: sTest,
		Srv:     s,
	}
}

func CreateTestOperator(t *testing.T, id uint64, version, operatorCert, operatorKey string) *TestOperator {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	r := chi.NewRouter()
	require.NoError(t, err)
	operatorPubKey := priv.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodeRSAPublicKey(operatorPubKey)
	require.NoError(t, err)
	swtch := operator.NewSwitch(priv, logger, []byte(version), pkBytes, id)
	tempDir, err := os.MkdirTemp("", "dkg")
	require.NoError(t, err)
	s := &operator.Server{
		Logger:     logger,
		Router:     r,
		State:      swtch,
		OutputPath: tempDir,
	}
	operator.RegisterRoutes(s)
	sTest, err := NewLocalHTTPSTestServer(s.Router, operatorCert, operatorKey)
	require.NoError(t, err)
	return &TestOperator{
		ID:      id,
		PrivKey: priv,
		HttpSrv: sTest,
		Srv:     s,
	}
}

func VerifySharesData(ids []uint64, keys []*rsa.PrivateKey, ks *wire.KeySharesCLI, owner common.Address, nonce uint16) error {
	sharesData, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
	if err != nil {
		return err
	}
	validatorPublicKey, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
	if err != nil {
		return err
	}
	operatorCount := len(keys)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("wrong sharesData length")
	}
	signature := sharesData[:signatureOffset]
	msg := []byte("Hello")
	if err := crypto.VerifyOwnerNonceSignature(signature, owner, validatorPublicKey, nonce); err != nil {
		return err
	}
	_ = utils.SplitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := utils.SplitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	sigs2 := make([][]byte, len(encryptedKeys))
	for i, enck := range encryptedKeys {
		priv := keys[i]
		share, err := rsaencryption.DecodeKey(priv, enck)
		if err != nil {
			return err
		}
		secret := &bls.SecretKey{}
		if err := secret.SetHexString(string(share)); err != nil {
			return err
		}
		sig := secret.SignByte(msg)
		sigs2[i] = sig.Serialize()
	}
	deserializedSigs2 := make([]*bls.Sign, len(sigs2))
	for i, sig := range sigs2 {
		deserializedSigs2[i] = &bls.Sign{}
		if err := deserializedSigs2[i].Deserialize(sig); err != nil {
			return err
		}
	}
	recon, err := crypto.RecoverBLSSignature(ids, deserializedSigs2)
	if err != nil {
		return err
	}
	blsPK := &bls.PublicKey{}
	if err := blsPK.Deserialize(validatorPublicKey); err != nil {
		return fmt.Errorf("could not deserialize validator pk %w", err)
	}
	// verify reconstructed sig
	if res := recon.VerifyByte(blsPK, msg); !res {
		return fmt.Errorf("could not reconstruct a valid signature")
	}
	return nil
}

func NewLocalHTTPSTestServer(handler http.Handler, operatorCert, operatorKey string) (*httptest.Server, error) {
	ts := httptest.NewUnstartedServer(handler)
	cert, err := tls.LoadX509KeyPair(operatorCert, operatorKey)
	if err != nil {
		return nil, err
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}}
	ts.StartTLS()
	return ts, nil
}
