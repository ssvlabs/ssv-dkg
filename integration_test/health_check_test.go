package integration_test

import (
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperators(t, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	var ips []string
	for _, s := range servers {
		ips = append(ips, s.HttpSrv.URL)
	}
	t.Run("positive", func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)
		dkgInitiator, err := initiator.New(ops.Clone(), zap.New(core), testVersion, nil, true)
		require.NoError(t, err)
		err = dkgInitiator.Ping([]string{ips[0]})
		require.NoError(t, err)
		matches := logs.FilterLevelExact(zapcore.InfoLevel).FilterMessageSnippet("operator online and healthy")
		require.GreaterOrEqual(t, matches.Len(), 1, "expected healthy operator log message")
	})
	t.Run("negative", func(t *testing.T) {
		servers[0].HttpSrv.Close()
		core, logs := observer.New(zap.DebugLevel)
		dkgInitiator, err := initiator.New(ops.Clone(), zap.New(core), testVersion, nil, true)
		require.NoError(t, err)
		err = dkgInitiator.Ping([]string{ips[0]})
		require.NoError(t, err)
		matches := logs.FilterLevelExact(zapcore.ErrorLevel).FilterMessageSnippet("operator not healthy")
		require.GreaterOrEqual(t, matches.Len(), 1, "expected unhealthy operator log message")
	})

	t.Run("spoofed_identity_rejected", func(t *testing.T) {
		t.Parallel()

		// Operator list contains the *expected* (known) public key for the endpoint.
		expectedPrivKey, _, err := spec_crypto.GenerateRSAKeys()
		require.NoError(t, err)
		attackerPrivKey, _, err := spec_crypto.GenerateRSAKeys()
		require.NoError(t, err)

		attackerPubBytes, err := spec_crypto.EncodeRSAPublicKey(&attackerPrivKey.PublicKey)
		require.NoError(t, err)

		const operatorID uint64 = 11
		pong := &wire.Pong{
			ID:                 operatorID,
			PubKey:             attackerPubBytes,
			Multisig:           true,
			EthClientConnected: true,
		}
		pongData, err := pong.MarshalSSZ()
		require.NoError(t, err)

		transport := &wire.Transport{
			Type:       wire.PongMessageType,
			Identifier: [24]byte{},
			Data:       pongData,
			Version:    []byte(testVersion),
		}
		transportBytes, err := transport.MarshalSSZ()
		require.NoError(t, err)
		sig, err := spec_crypto.SignRSA(attackerPrivKey, transportBytes)
		require.NoError(t, err)

		signed := &wire.SignedTransport{
			Message:   transport,
			Signer:    attackerPubBytes,
			Signature: sig,
		}
		respBytes, err := signed.MarshalSSZ()
		require.NoError(t, err)

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health_check" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
		}))
		t.Cleanup(ts.Close)

		core, logs := observer.New(zap.DebugLevel)
		dkgInitiator, err := initiator.New(wire.OperatorsCLI{
			{
				Addr:   ts.URL,
				ID:     operatorID,
				PubKey: &expectedPrivKey.PublicKey,
			},
		}, zap.New(core), testVersion, nil, true)
		require.NoError(t, err)

		err = dkgInitiator.Ping([]string{ts.URL})
		require.NoError(t, err)
		matches := logs.FilterLevelExact(zapcore.ErrorLevel).FilterMessageSnippet("operator not healthy")
		require.GreaterOrEqual(t, matches.Len(), 1, "expected spoofed identity to be rejected")
	})

	t.Run("operator_id_mismatch_rejected", func(t *testing.T) {
		t.Parallel()

		expectedPrivKey, _, err := spec_crypto.GenerateRSAKeys()
		require.NoError(t, err)

		expectedPubBytes, err := spec_crypto.EncodeRSAPublicKey(&expectedPrivKey.PublicKey)
		require.NoError(t, err)

		const expectedOperatorID uint64 = 11
		const mismatchedOperatorID uint64 = 22
		pong := &wire.Pong{
			ID:                 mismatchedOperatorID,
			PubKey:             expectedPubBytes,
			Multisig:           true,
			EthClientConnected: true,
		}
		pongData, err := pong.MarshalSSZ()
		require.NoError(t, err)

		transport := &wire.Transport{
			Type:       wire.PongMessageType,
			Identifier: [24]byte{},
			Data:       pongData,
			Version:    []byte(testVersion),
		}
		transportBytes, err := transport.MarshalSSZ()
		require.NoError(t, err)
		sig, err := spec_crypto.SignRSA(expectedPrivKey, transportBytes)
		require.NoError(t, err)

		signed := &wire.SignedTransport{
			Message:   transport,
			Signer:    expectedPubBytes,
			Signature: sig,
		}
		respBytes, err := signed.MarshalSSZ()
		require.NoError(t, err)

		ts := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/health_check" {
				http.NotFound(w, r)
				return
			}
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(respBytes)
		}))
		t.Cleanup(ts.Close)

		core, logs := observer.New(zap.DebugLevel)
		dkgInitiator, err := initiator.New(wire.OperatorsCLI{
			{
				Addr:   ts.URL,
				ID:     expectedOperatorID,
				PubKey: &expectedPrivKey.PublicKey,
			},
		}, zap.New(core), testVersion, nil, true)
		require.NoError(t, err)

		err = dkgInitiator.Ping([]string{ts.URL})
		require.NoError(t, err)

		entries := logs.FilterLevelExact(zapcore.ErrorLevel).FilterMessageSnippet("operator not healthy").All()
		require.NotEmpty(t, entries, "expected unhealthy operator log message")

		var found bool
		for _, e := range entries {
			ctx := e.ContextMap()
			errVal := fmt.Sprint(ctx["error"])
			if strings.Contains(errVal, "does not match expected operator ID") {
				found = true
				break
			}
		}
		require.True(t, found, "expected operator ID mismatch to be rejected")
	})
}
