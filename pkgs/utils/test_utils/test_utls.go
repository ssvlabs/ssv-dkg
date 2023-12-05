package test_utils

import (
	"context"
	"crypto/rsa"
	"errors"
	"fmt"
	"net/http/httptest"
	"testing"

	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/operator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/bloxapp/ssv/storage/kv"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

type TestOperator struct {
	ID      uint64
	PrivKey *rsa.PrivateKey
	HttpSrv *httptest.Server
	Srv     *operator.Server
}

func ParseAsError(msg []byte) (error, error) {
	sszerr := &wire.ErrSSZ{}
	err := sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, err
	}

	return errors.New(string(sszerr.Error)), nil
}

func CreateTestOperatorFromFile(t *testing.T, id uint64, examplePath string) *TestOperator {
	if err := logging.SetGlobalLogger("info", "capital", "console", nil); err != nil {
		panic(err)
	}
	logger := zap.L().Named("operator-tests")
	priv, err := crypto.EncryptedPrivateKey(examplePath+"operator"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	r := chi.NewRouter()
	db, err := kv.NewInMemory(logging.TestLogger(t), basedb.Options{
		Reporting: true,
		Ctx:       context.Background(),
		Path:      t.TempDir(),
	})
	require.NoError(t, err)
	operatorPubKey := priv.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodePublicKey(operatorPubKey)
	if err != nil {
		panic(err)
	}
	swtch := operator.NewSwitch(priv, logger, db, []byte("v1.0.2"), pkBytes)
	s := &operator.Server{
		Logger: logger,
		Router: r,
		State:  swtch,
	}
	operator.RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &TestOperator{
		ID:      id,
		PrivKey: priv,
		HttpSrv: sTest,
		Srv:     s,
	}
}

func CreateTestOperator(t *testing.T, id uint64, version string) *TestOperator {
	if err := logging.SetGlobalLogger("info", "capital", "console", nil); err != nil {
		panic(err)
	}
	logger := zap.L().Named("integration-tests")
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	r := chi.NewRouter()
	db, err := kv.NewInMemory(logging.TestLogger(t), basedb.Options{
		Reporting: true,
		Ctx:       context.Background(),
		Path:      t.TempDir(),
	})
	require.NoError(t, err)
	operatorPubKey := priv.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodePublicKey(operatorPubKey)
	if err != nil {
		panic(err)
	}
	swtch := operator.NewSwitch(priv, logger, db, []byte(version), pkBytes)
	s := &operator.Server{
		Logger: logger,
		Router: r,
		State:  swtch,
	}
	operator.RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &TestOperator{
		ID:      id,
		PrivKey: priv,
		HttpSrv: sTest,
		Srv:     s,
	}
}
