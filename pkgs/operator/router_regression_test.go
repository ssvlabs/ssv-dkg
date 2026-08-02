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
	"github.com/ssvlabs/dkg-spec/eip1271"
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
	// Default stub: any owner address is an EOA, so signature recovery is attempted.
	return newRouterTestEnvWithETH(t, &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	})
}

// newRouterTestEnvWithETH builds the same in-process server against a caller-supplied eth
// client, so a test can arrange for owner authorisation to succeed and reach the ceremony.
func newRouterTestEnvWithETH(t *testing.T, eth eip1271.ETHClient) *routerTestEnv {
	t.Helper()
	version := []byte("test.version")

	opPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	opPub, err := spec_crypto.EncodeRSAPublicKey(&opPriv.PublicKey)
	require.NoError(t, err)
	const opID = uint64(1)

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

// newCeremonyRouterEnv returns a router env whose eth stub treats contractOwner as a
// contract that approves any signature, so a request clears owner authorisation and fails
// inside the ceremony instead of in front of it.
func newCeremonyRouterEnv(t *testing.T) *routerTestEnv {
	t.Helper()
	return newRouterTestEnvWithETH(t, &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			ret := make([]byte, 32)
			copy(ret[:4], eip1271.MAGIC_VALUE[:]) // valid EIP-1271 signature
			return ret, nil
		},
		CodeAtMap: map[common.Address]bool{contractOwner: true},
	})
}

// transportFor marshals a ceremony message into a transport at the given version.
func (e *routerTestEnv) transportFor(t *testing.T, msgType wire.TransportType, msg wire.SSZMarshaller, version []byte) *wire.Transport {
	t.Helper()
	data, err := msg.MarshalSSZ()
	require.NoError(t, err)
	var reqID [24]byte
	return &wire.Transport{Type: msgType, Identifier: reqID, Data: data, Version: version}
}

// signAsInitiator wraps a transport in a signature from a throwaway initiator key. The
// operator authenticates the initiator's own key rather than an allow-list, so any key works.
func signAsInitiator(t *testing.T, message *wire.Transport) *wire.SignedTransport {
	t.Helper()
	msgBytes, err := message.MarshalSSZ()
	require.NoError(t, err)
	initPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	initPub, err := spec_crypto.EncodeRSAPublicKey(&initPriv.PublicKey)
	require.NoError(t, err)
	initSig, err := spec_crypto.SignRSA(initPriv, msgBytes)
	require.NoError(t, err)
	return &wire.SignedTransport{Message: message, Signer: initPub, Signature: initSig}
}

// resignBatchSignedByForeignKey builds a well-formed resign batch whose proof is signed by
// a key that is not this operator's, so it is rejected deep inside the ceremony, by
// LocalOwner.Resign, after owner authorisation has already succeeded.
func (e *routerTestEnv) resignBatchSignedByForeignKey(t *testing.T) *wire.SignedResign {
	t.Helper()
	validatorPK := bytesRepeat(0xAA, 48)
	proof := &spec.Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  bytesRepeat(0x01, 128),
		SharePubKey:     bytesRepeat(0x00, 48),
		Owner:           contractOwner,
	}
	root, err := proof.HashTreeRoot()
	require.NoError(t, err)
	foreignPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	signature, err := spec_crypto.SignRSA(foreignPriv, root[:])
	require.NoError(t, err)

	return &wire.SignedResign{
		Messages: []*wire.ResignMessage{{
			Operators: []*spec.Operator{{ID: e.opID, PubKey: e.opPub}},
			Resign: &spec.Resign{
				ValidatorPubKey:       validatorPK,
				WithdrawalCredentials: eth1Creds(),
				Owner:                 contractOwner,
				Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			},
			Proofs: []*spec.SignedProof{{Proof: proof, Signature: signature}},
		}},
		Signature: bytesRepeat(0x00, 65),
	}
}

// reshareBatchStructurallyInvalid builds a reshare batch whose operator sets cannot carry
// the threshold it advertises, so it is rejected by the structural checks.
func (e *routerTestEnv) reshareBatchStructurallyInvalid(t *testing.T) *wire.SignedReshare {
	t.Helper()
	validatorPK := bytesRepeat(0xAA, 48)
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
}

// TestCeremonyRoutesMaskFailureDetail asserts /resign and /reshare tell the initiator
// nothing about WHY a ceremony failed beyond a fixed code. The response to a failed
// ceremony is an oracle if it varies with the request, so the body must be the same code
// whatever went wrong and wherever it went wrong.
//
// The third row is a preflight failure rather than a ceremony one. It is here to bound the
// one carve-out these routes make — a version mismatch is reported verbatim — by pinning a
// neighbouring error raised a few lines away in the same function, which must stay masked.
func TestCeremonyRoutesMaskFailureDetail(t *testing.T) {
	tests := []struct {
		name          string
		route         string
		msgType       wire.TransportType
		message       func(e *routerTestEnv) wire.SSZMarshaller
		validInitSig  bool
		mustNotAppear []string
	}{
		{
			name:    "resign proof signed by a foreign key",
			route:   "/resign",
			msgType: wire.SignedResignMessageType,
			message: func(e *routerTestEnv) wire.SSZMarshaller {
				return e.resignBatchSignedByForeignKey(t)
			},
			validInitSig:  true,
			mustNotAppear: []string{"crypto/rsa", "verification", "validate resign message"},
		},
		{
			name:    "reshare structurally invalid",
			route:   "/reshare",
			msgType: wire.SignedReshareMessageType,
			message: func(e *routerTestEnv) wire.SSZMarshaller {
				return e.reshareBatchStructurallyInvalid(t)
			},
			validInitSig:  true,
			mustNotAppear: []string{"threshold", "operators"},
		},
		{
			name:    "resign with an invalid initiator signature",
			route:   "/resign",
			msgType: wire.SignedResignMessageType,
			message: func(e *routerTestEnv) wire.SSZMarshaller {
				return e.resignBatchSignedByForeignKey(t)
			},
			validInitSig:  false,
			mustNotAppear: []string{"crypto/rsa", "isn't valid", "signature"},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newCeremonyRouterEnv(t)
			message := env.transportFor(t, tc.msgType, tc.message(env), env.version)

			var signed *wire.SignedTransport
			if tc.validInitSig {
				signed = signAsInitiator(t, message)
			} else {
				valid := signAsInitiator(t, message)
				signed = &wire.SignedTransport{
					Message:   message,
					Signer:    valid.Signer,
					Signature: bytesRepeat(0x00, 256), // not a signature over this message
				}
			}

			recorder := env.post(t, tc.route, signed)

			require.Equal(t, http.StatusBadRequest, recorder.Code)
			body, err := wire.ParseAsError(recorder.Body.Bytes())
			require.NoError(t, err)
			require.Equal(t, string(wire.InitiatorErrorCodeCeremonyFailed), body,
				"a failed ceremony must present exactly the generic code and nothing else")
			for _, leak := range tc.mustNotAppear {
				require.NotContains(t, body, leak)
			}
		})
	}
}

// TestCeremonyRoutesReportVersionMismatch asserts the one failure these routes do report
// verbatim. Operators and initiator must run identical versions, so a mismatch is both the
// most likely failure after an upgrade and one that says nothing about ceremony material —
// reporting it as the generic code would leave operators with no way to diagnose it.
func TestCeremonyRoutesReportVersionMismatch(t *testing.T) {
	tests := []struct {
		name    string
		route   string
		msgType wire.TransportType
		message func(e *routerTestEnv) wire.SSZMarshaller
	}{
		{
			name:    "resign",
			route:   "/resign",
			msgType: wire.SignedResignMessageType,
			message: func(e *routerTestEnv) wire.SSZMarshaller { return e.resignBatchSignedByForeignKey(t) },
		},
		{
			name:    "reshare",
			route:   "/reshare",
			msgType: wire.SignedReshareMessageType,
			message: func(e *routerTestEnv) wire.SSZMarshaller { return e.reshareBatchStructurallyInvalid(t) },
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newCeremonyRouterEnv(t)
			message := env.transportFor(t, tc.msgType, tc.message(env), []byte("other.version"))
			signed := signAsInitiator(t, message)

			recorder := env.post(t, tc.route, signed)

			require.Equal(t, http.StatusBadRequest, recorder.Code)
			body, err := wire.ParseAsError(recorder.Body.Bytes())
			require.NoError(t, err)
			require.Equal(t, "wrong version: remote other.version local test.version", body,
				"a version mismatch must name both versions so it can be acted on")
			require.NotContains(t, body, string(wire.InitiatorErrorCodeCeremonyFailed))
		})
	}
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
