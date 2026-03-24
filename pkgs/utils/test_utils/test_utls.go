package test_utils

import (
	"crypto/rsa"
	"crypto/tls"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/operator"
)

type TestOperator struct {
	ID      uint64
	PrivKey *rsa.PrivateKey
	HttpSrv *httptest.Server
	Srv     *operator.Server
}

func CreateTestOperatorFromFile(t *testing.T, id uint64, opPath, version, operatorCert, operatorKey string, stubClient *stubs.Client) *TestOperator {
	logger := zap.Must(zap.NewDevelopment()).Named("operator-tests")
	privKey, err := os.ReadFile(filepath.Clean(opPath + "/encrypted_private_key.json"))
	if err != nil {
		logger.Fatal("failed to read file", zap.Error(err))
		return nil
	}
	pass, err := os.ReadFile(filepath.Clean(opPath + "/password"))
	if err != nil {
		logger.Fatal("failed to read file", zap.Error(err))
		return nil
	}
	priv, err := crypto.DecryptRSAKeystore(privKey, string(pass))
	require.NoError(t, err)
	r := chi.NewRouter()
	operatorPubKey := priv.Public().(*rsa.PublicKey)
	pkBytes, err := spec_crypto.EncodeRSAPublicKey(operatorPubKey)
	require.NoError(t, err)
	swtch := operator.NewSwitch(priv, logger, []byte(version), pkBytes, id, stubClient)
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

func CreateTestOperator(t *testing.T, id uint64, version, operatorCert, operatorKey string, stubClient *stubs.Client) *TestOperator {
	logger := zap.Must(zap.NewDevelopment()).Named("integration-tests")
	priv, _, err := spec_crypto.GenerateRSAKeys()
	require.NoError(t, err)
	r := chi.NewRouter()
	operatorPubKey := priv.Public().(*rsa.PublicKey)
	pkBytes, err := spec_crypto.EncodeRSAPublicKey(operatorPubKey)
	require.NoError(t, err)
	swtch := operator.NewSwitch(priv, logger, []byte(version), pkBytes, id, stubClient)
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

func NewLocalHTTPSTestServer(handler http.Handler, operatorCert, operatorKey string) (*httptest.Server, error) {
	ts := httptest.NewUnstartedServer(handler)
	cert, err := tls.LoadX509KeyPair(operatorCert, operatorKey)
	if err != nil {
		return nil, err
	}
	ts.TLS = &tls.Config{Certificates: []tls.Certificate{cert}} //nolint:gosec // test server
	ts.StartTLS()
	return ts, nil
}
