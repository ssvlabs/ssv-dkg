package operator

import (
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/go-chi/chi/v5"
	"github.com/imroc/req/v3"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/consts"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/load"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

const exmaplePath = "../../examples/"

func TestRateLimit(t *testing.T) {
	srv := CreateTestOperator(t, 1)
	t.Run("test init route rate limit", func(t *testing.T) {
		ops := make(map[uint64]initiator.Operator)
		ops[1] = initiator.Operator{Addr: srv.httpSrv.URL, ID: 1, PubKey: &srv.privKey.PublicKey}

		parts := make([]*wire.Operator, 0)
		for _, id := range []uint64{1} {
			op, ok := ops[id]
			if !ok {
				t.Fatalf("no op")
			}
			pkBytes, err := crypto.EncodePublicKey(op.PubKey)
			if err != nil {
				require.NoError(t, err)
			}
			parts = append(parts, &wire.Operator{
				ID:     op.ID,
				PubKey: pkBytes,
			})
		}

		init := &wire.Init{
			Operators:             parts,
			T:                     3,
			WithdrawalCredentials: common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(),
			Fork:                  [4]byte{0, 0, 0, 0},
			Owner:                 common.HexToAddress("0x0000000000000000000000000000000000000007"),
			Nonce:                 0,
		}
		sszinit, err := init.MarshalSSZ()
		require.NoError(t, err)

		ts := &wire.Transport{
			Type:       wire.InitMessageType,
			Identifier: [24]byte{},
			Data:       sszinit,
		}

		tsssz, err := ts.MarshalSSZ()
		require.NoError(t, err)

		client := req.C()
		r := client.R()

		r.SetBodyBytes(tsssz)

		// Send requests
		errChan := make(chan []byte)
		time.Sleep(time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer close(errChan)
			defer wg.Done()
			for i := 0; i < 100; i++ {
				res, err := r.Post(fmt.Sprintf("%v/%v", srv.httpSrv.URL, "init"))
				require.NoError(t, err)
				if res.Status == "429 Too Many Requests" {
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					errChan <- b
				}
			}
		}()
		for errResp := range errChan {
			require.NotEmpty(t, errResp)
			require.Equal(t, ErrTooManyDKGRequests, string(errResp))
		}
		wg.Wait()
	})
	t.Run("test general rate limit", func(t *testing.T) {
		client := req.C()
		r := client.R()

		r.SetBodyBytes([]byte{})

		// Send requests
		errChan := make(chan []byte)
		time.Sleep(time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer close(errChan)
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				res, err := r.Post(fmt.Sprintf("%v/%v", srv.httpSrv.URL, "dkg"))
				require.NoError(t, err)
				if res.Status == "429 Too Many Requests" {
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					errChan <- b
				}
			}
		}()
		for errResp := range errChan {
			require.NotEmpty(t, errResp)
			require.Equal(t, ErrTooManyOperatorRequests, string(errResp))
		}
		wg.Wait()
	})
	srv.httpSrv.Close()
}

func TestWrongInitiatorSignature(t *testing.T) {
	if err := logging.SetGlobalLogger("info", "capital", "console", nil); err != nil {
		panic(err)
	}
	logger := zap.L().Named("operator-tests")
	ops := make(map[uint64]initiator.Operator)
	srv1 := CreateTestOperator(t, 1)
	srv2 := CreateTestOperator(t, 2)
	srv3 := CreateTestOperator(t, 3)
	srv4 := CreateTestOperator(t, 4)
	ops[1] = initiator.Operator{Addr: srv1.httpSrv.URL, ID: 1, PubKey: &srv1.privKey.PublicKey}
	ops[2] = initiator.Operator{Addr: srv2.httpSrv.URL, ID: 2, PubKey: &srv2.privKey.PublicKey}
	ops[3] = initiator.Operator{Addr: srv3.httpSrv.URL, ID: 3, PubKey: &srv3.privKey.PublicKey}
	ops[4] = initiator.Operator{Addr: srv4.httpSrv.URL, ID: 4, PubKey: &srv4.privKey.PublicKey}
	t.Run("test wrong pub key in init message", func(t *testing.T) {
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
		owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
		ids := []uint64{1, 2, 3, 4}

		c := initiator.New(priv, ops, logger)
		// compute threshold (3f+1)
		threshold := len(ids) - ((len(ids) - 1) / 3)
		parts := make([]*wire.Operator, 0)
		for _, id := range ids {
			op, ok := c.Operators[id]
			require.True(t, ok)
			pkBytes, err := crypto.EncodePublicKey(op.PubKey)
			require.NoError(t, err)
			parts = append(parts, &wire.Operator{
				ID:     op.ID,
				PubKey: pkBytes,
			})
		}
		// Add messages verification coming form operators
		verify, err := c.CreateVerifyFunc(parts)
		require.NoError(t, err)
		c.VerifyFunc = verify
		// Change pub key
		_, newPv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		newPriv, err := rsaencryption.ConvertPemToPrivateKey(string(newPv))
		require.NoError(t, err)
		wrongPub, err := crypto.EncodePublicKey(&newPriv.PublicKey)
		require.NoError(t, err)
		c.Logger.Info(fmt.Sprintf("Initiator ID: %x", sha256.Sum256(c.PrivateKey.PublicKey.N.Bytes())))
		// make init message
		init := &wire.Init{
			Operators:             parts,
			T:                     uint64(threshold),
			WithdrawalCredentials: withdraw.Bytes(),
			Fork:                  [4]byte{0, 0, 0, 0},
			Owner:                 owner,
			Nonce:                 0,
			InitiatorPublicKey:    wrongPub,
		}
		id := c.NewID()
		results, err := c.SendInitMsg(init, id)
		require.NoError(t, err)
		var errs []error
		for i := 0; i < len(results); i++ {
			msg := results[i]
			tsp := &wire.SignedTransport{}
			if err := tsp.UnmarshalSSZ(msg); err != nil {
				// try parsing an error
				errmsg, parseErr := parseAsError(msg)
				require.NoError(t, parseErr)
				errs = append(errs, errmsg)
			}
		}
		require.Equal(t, 4, len(errs))
		for _, err := range errs {
			require.ErrorContains(t, err, "init message signature isn't valid")
		}
	})
	t.Run("test wrong signature of init message", func(t *testing.T) {
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
		owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
		ids := []uint64{1, 2, 3, 4}

		c := initiator.New(priv, ops, logger)
		// compute threshold (3f+1)
		threshold := len(ids) - ((len(ids) - 1) / 3)
		parts := make([]*wire.Operator, 0)
		for _, id := range ids {
			op, ok := c.Operators[id]
			require.True(t, ok)
			pkBytes, err := crypto.EncodePublicKey(op.PubKey)
			require.NoError(t, err)
			parts = append(parts, &wire.Operator{
				ID:     op.ID,
				PubKey: pkBytes,
			})
		}
		// Add messages verification coming form operators
		verify, err := c.CreateVerifyFunc(parts)
		require.NoError(t, err)
		c.VerifyFunc = verify
		wrongPub, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
		require.NoError(t, err)
		c.Logger.Info(fmt.Sprintf("Initiator ID: %x", sha256.Sum256(c.PrivateKey.PublicKey.N.Bytes())))
		// make init message
		init := &wire.Init{
			Operators:             parts,
			T:                     uint64(threshold),
			WithdrawalCredentials: withdraw.Bytes(),
			Fork:                  [4]byte{0, 0, 0, 0},
			Owner:                 owner,
			Nonce:                 0,
			InitiatorPublicKey:    wrongPub,
		}
		id := c.NewID()
		sszinit, err := init.MarshalSSZ()
		require.NoError(t, err)
		initMessage := &wire.Transport{
			Type:       wire.InitMessageType,
			Identifier: id,
			Data:       sszinit,
		}
		sig, err := hex.DecodeString("a32d0f695aad4a546b5507bb6b7cf43be7c54385589bbc6616bb97e58e839b596e8e827f8309488e6adc86562f7662738f46ae57f166e226913d66d6134149e8c6d6c60676da480c3ace2ea18f031ca4cfb51fa11a0595e63fe5808440b46c45d90e020f77bf35e64d7886ecf2e6f825168c955110753f73b37a5492191bd60a1bc7779f550b60aa37150ca2d16c15d33f014bca3dcfbb7a937312a51eb8d059a95203492e669238e5effdd38893b851d04f70cd58ad7ba0da7b21cb826b7397dbdffcbf6d66a8bcbf4e081a568c6e647e8d942c838533907ab7190c8a63eac73bec612cc1c44686164e734abec87ae223959b0f09f0c21cd99945e5319cb5a9")
		require.NoError(t, err)
		// Create signed init message
		signedInitMsg := &wire.SignedTransport{
			Message:   initMessage,
			Signer:    0,
			Signature: sig}
		signedInitMsgBts, err := signedInitMsg.MarshalSSZ()
		require.NoError(t, err)
		results, err := c.SendToAll(consts.API_INIT_URL, signedInitMsgBts)
		require.NoError(t, err)
		var errs []error
		for i := 0; i < len(results); i++ {
			msg := results[i]
			tsp := &wire.SignedTransport{}
			if err := tsp.UnmarshalSSZ(msg); err != nil {
				// try parsing an error
				errmsg, parseErr := parseAsError(msg)
				require.NoError(t, parseErr)
				errs = append(errs, errmsg)
			}
		}
		require.Equal(t, 4, len(errs))
		for _, err := range errs {
			require.ErrorContains(t, err, "init message signature isn't valid")
		}
	})
	srv1.httpSrv.Close()
	srv2.httpSrv.Close()
	srv3.httpSrv.Close()
	srv4.httpSrv.Close()
}

func CreateTestOperator(t *testing.T, id uint64) *testOperator {
	if err := logging.SetGlobalLogger("info", "capital", "console", nil); err != nil {
		panic(err)
	}
	logger := zap.L().Named("operator-tests")
	priv, err := load.EncryptedPrivateKey(exmaplePath+"operator"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	r := chi.NewRouter()
	swtch := &Switch{
		Logger:           logger,
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		Instances:        make(map[InstanceID]Instance, MaxInstances),
		PrivateKey:       priv,
	}

	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &Server{
		Logger: logger,
		Router: r,
		State:  swtch,
	}
	RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &testOperator{
		id:      id,
		privKey: priv,
		httpSrv: sTest,
		srv:     s,
	}
}

type testOperator struct {
	id      uint64
	privKey *rsa.PrivateKey
	httpSrv *httptest.Server
	srv     *Server
}

func parseAsError(msg []byte) (error, error) {
	sszerr := &wire.ErrSSZ{}
	err := sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, err
	}

	return errors.New(string(sszerr.Error)), nil
}
