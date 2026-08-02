package operator

// Regression tests for request-level fault containment.
//
// The invariant under test: a malformed request cannot take the server down. These
// must be driven through the router, because containment is installed as router
// middleware — calling a handler or the Switch directly bypasses it.

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/go-chi/chi/v5"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// routerTestEnv is a Server with the real routes registered, driven in-process.
type routerTestEnv struct {
	server  *Server
	opPub   []byte
	opID    uint64
	version []byte
}

func newRouterTestEnv(t *testing.T) *routerTestEnv {
	t.Helper()
	version := []byte("test.version")

	opPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	opPub, err := spec_crypto.EncodeRSAPublicKey(&opPriv.PublicKey)
	require.NoError(t, err)
	const opID = uint64(1)

	// Default stub: any owner address is an EOA, so signature recovery is attempted.
	eth := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}

	server := &Server{
		Logger: zap.NewNop(),
		Router: chi.NewRouter(),
		State:  NewSwitch(opPriv, zap.NewNop(), version, opPub, opID, eth),
	}
	RegisterRoutes(server)

	return &routerTestEnv{server: server, opPub: opPub, opID: opID, version: version}
}

// post sends a signed transport to the given route through the router and returns
// the response recorder.
func (e *routerTestEnv) post(t *testing.T, route string, signed *wire.SignedTransport) *httptest.ResponseRecorder {
	t.Helper()
	body, err := signed.MarshalSSZ()
	require.NoError(t, err)

	recorder := httptest.NewRecorder()
	request := httptest.NewRequest(http.MethodPost, route, bytes.NewReader(body))
	e.server.Router.ServeHTTP(recorder, request)
	return recorder
}

// nonRSAPublicKey returns an encoded public key that parses as valid PEM but is not
// an RSA key.
func nonRSAPublicKey(t *testing.T) []byte {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	der, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	require.NoError(t, err)
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})
	return []byte(base64.StdEncoding.EncodeToString(pemBytes))
}

// TestRouterContainsNonRSAInitiatorKey asserts a request whose initiator key is a
// well-formed but non-RSA public key is contained instead of taking the server down.
func TestRouterContainsNonRSAInitiatorKey(t *testing.T) {
	validatorPK := bytesRepeat(0xAA, 48)

	tests := []struct {
		name    string
		route   string
		msgType wire.TransportType
		data    func(e *routerTestEnv) wire.SSZMarshaller
	}{
		{
			name:    "init",
			route:   "/init",
			msgType: wire.InitMessageType,
			data: func(e *routerTestEnv) wire.SSZMarshaller {
				// a structurally valid init message, so the request reaches the point
				// where the initiator key is parsed
				return &spec.Init{
					Operators: []*spec.Operator{
						{ID: e.opID, PubKey: e.opPub},
						{ID: e.opID + 1, PubKey: foreignOperatorKey(t)},
						{ID: e.opID + 2, PubKey: foreignOperatorKey(t)},
						{ID: e.opID + 3, PubKey: foreignOperatorKey(t)},
					},
					T:                     3,
					WithdrawalCredentials: eth1Creds(),
					Owner:                 contractOwner,
					Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
				}
			},
		},
		{
			name:    "resign",
			route:   "/resign",
			msgType: wire.SignedResignMessageType,
			data: func(e *routerTestEnv) wire.SSZMarshaller {
				return &wire.SignedResign{
					Messages: []*wire.ResignMessage{{
						Operators: []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
						Resign: &spec.Resign{
							ValidatorPubKey:       validatorPK,
							WithdrawalCredentials: eth1Creds(),
							Owner:                 contractOwner,
							Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
						},
						Proofs: []*spec.SignedProof{{Proof: &spec.Proof{
							ValidatorPubKey: validatorPK,
							EncryptedShare:  bytesRepeat(0x01, 128),
							SharePubKey:     bytesRepeat(0x00, 48),
							Owner:           contractOwner,
						}, Signature: bytesRepeat(0x00, 256)}},
					}},
					Signature: bytesRepeat(0x00, 65),
				}
			},
		},
		{
			name:    "reshare",
			route:   "/reshare",
			msgType: wire.SignedReshareMessageType,
			data: func(e *routerTestEnv) wire.SSZMarshaller {
				return &wire.SignedReshare{
					Messages: []*wire.ReshareMessage{{
						Reshare: &spec.Reshare{
							ValidatorPubKey:       validatorPK,
							OldOperators:          []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
							NewOperators:          []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
							OldT:                  3,
							NewT:                  3,
							WithdrawalCredentials: eth1Creds(),
							Owner:                 contractOwner,
							Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
						},
						Proofs: []*spec.SignedProof{{Proof: &spec.Proof{
							ValidatorPubKey: validatorPK,
							EncryptedShare:  bytesRepeat(0x01, 128),
							SharePubKey:     bytesRepeat(0x00, 48),
							Owner:           contractOwner,
						}, Signature: bytesRepeat(0x00, 256)}},
					}},
					Signature: bytesRepeat(0x00, 65),
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newRouterTestEnv(t)
			data, err := tc.data(env).MarshalSSZ()
			require.NoError(t, err)

			var reqID [24]byte
			signed := &wire.SignedTransport{
				Message:   &wire.Transport{Type: tc.msgType, Identifier: reqID, Data: data, Version: env.version},
				Signer:    nonRSAPublicKey(t),
				Signature: bytesRepeat(0x00, 256),
			}

			var recorder *httptest.ResponseRecorder
			require.NotPanics(t, func() {
				recorder = env.post(t, tc.route, signed)
			}, "a non-RSA initiator key must not escape as a panic")
			require.NotEqual(t, http.StatusOK, recorder.Code)
		})
	}
}

// TestRouterContainsShortOwnerSignature asserts a batch carrying an owner signature
// shorter than an ECDSA signature is contained instead of taking the server down.
func TestRouterContainsShortOwnerSignature(t *testing.T) {
	validatorPK := bytesRepeat(0xAA, 48)
	eoaOwner := common.HexToAddress("0x000000000000000000000000000000000C71c71c")

	tests := []struct {
		name    string
		route   string
		msgType wire.TransportType
		data    func(e *routerTestEnv) wire.SSZMarshaller
	}{
		{
			name:    "resign",
			route:   "/resign",
			msgType: wire.SignedResignMessageType,
			data: func(e *routerTestEnv) wire.SSZMarshaller {
				return &wire.SignedResign{
					Messages: []*wire.ResignMessage{{
						Operators: []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
						Resign: &spec.Resign{
							ValidatorPubKey:       validatorPK,
							WithdrawalCredentials: eth1Creds(),
							Owner:                 eoaOwner,
							Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
						},
						Proofs: []*spec.SignedProof{{Proof: &spec.Proof{
							ValidatorPubKey: validatorPK,
							EncryptedShare:  bytesRepeat(0x01, 128),
							SharePubKey:     bytesRepeat(0x00, 48),
							Owner:           eoaOwner,
						}, Signature: bytesRepeat(0x00, 256)}},
					}},
					Signature: bytesRepeat(0x00, 8), // shorter than an ECDSA signature
				}
			},
		},
		{
			name:    "reshare",
			route:   "/reshare",
			msgType: wire.SignedReshareMessageType,
			data: func(e *routerTestEnv) wire.SSZMarshaller {
				return &wire.SignedReshare{
					Messages: []*wire.ReshareMessage{{
						Reshare: &spec.Reshare{
							ValidatorPubKey:       validatorPK,
							OldOperators:          []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
							NewOperators:          []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
							OldT:                  3,
							NewT:                  3,
							WithdrawalCredentials: eth1Creds(),
							Owner:                 eoaOwner,
							Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
						},
						Proofs: []*spec.SignedProof{{Proof: &spec.Proof{
							ValidatorPubKey: validatorPK,
							EncryptedShare:  bytesRepeat(0x01, 128),
							SharePubKey:     bytesRepeat(0x00, 48),
							Owner:           eoaOwner,
						}, Signature: bytesRepeat(0x00, 256)}},
					}},
					Signature: bytesRepeat(0x00, 8),
				}
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newRouterTestEnv(t)
			data, err := tc.data(env).MarshalSSZ()
			require.NoError(t, err)

			var reqID [24]byte
			message := &wire.Transport{Type: tc.msgType, Identifier: reqID, Data: data, Version: env.version}
			msgBytes, err := message.MarshalSSZ()
			require.NoError(t, err)

			initPriv, err := rsa.GenerateKey(rand.Reader, 2048)
			require.NoError(t, err)
			initPub, err := spec_crypto.EncodeRSAPublicKey(&initPriv.PublicKey)
			require.NoError(t, err)
			initSig, err := spec_crypto.SignRSA(initPriv, msgBytes)
			require.NoError(t, err)

			signed := &wire.SignedTransport{Message: message, Signer: initPub, Signature: initSig}

			var recorder *httptest.ResponseRecorder
			require.NotPanics(t, func() {
				recorder = env.post(t, tc.route, signed)
			}, "a short owner signature must not escape as a panic")
			require.NotEqual(t, http.StatusOK, recorder.Code)
		})
	}
}
