package operator

// Regression tests for resign/reshare batch handling.
//
// The invariants under test: one owner signature authorises exactly the messages
// that belong to that owner, the whole batch is rejected if any message does not,
// and malformed batches are rejected rather than indexed into.

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// recordingClient wraps the eth stub and records every address whose account
// code is queried — i.e. every owner the operator actually checks a signature
// against.
type recordingClient struct {
	*stubs.Client
	queried *[]common.Address
}

func (c *recordingClient) CodeAt(ctx context.Context, addr common.Address, block *big.Int) ([]byte, error) {
	*c.queried = append(*c.queried, addr)
	return c.Client.CodeAt(ctx, addr, block)
}

func bytesRepeat(b byte, n int) []byte {
	out := make([]byte, n)
	for i := range out {
		out[i] = b
	}
	return out
}

func eth1Creds() []byte {
	c := make([]byte, 32)
	c[0] = 1 // ETH1WithdrawalPrefix
	return c
}

// contractOwner is an EIP-1271 owner whose contract approves any signature.
var contractOwner = common.HexToAddress("0x00000000000000000000000000000000A77ac4e5")

// otherOwner never authorises anything and stays an EOA.
var otherOwner = common.HexToAddress("0x000000000000000000000000000000000C71c71c")

// batchTestEnv is a Switch wired to an eth stub that rubber-stamps signatures for
// contractOwner, plus a record of every owner whose authorisation was checked.
type batchTestEnv struct {
	swtch   *Switch
	opID    uint64
	opPub   []byte
	version []byte
	queried *[]common.Address
}

func newBatchTestEnv(t *testing.T) *batchTestEnv {
	t.Helper()
	logger := zap.NewNop()
	version := []byte("test.version")

	opPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	opPub, err := spec_crypto.EncodeRSAPublicKey(&opPriv.PublicKey)
	require.NoError(t, err)
	const opID = uint64(1)

	queried := &[]common.Address{}
	eth := &recordingClient{
		Client: &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32)
				copy(ret[:4], eip1271.MAGIC_VALUE[:]) // valid EIP-1271 signature
				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{contractOwner: true}, // contract; other owners stay EOA
		},
		queried: queried,
	}

	return &batchTestEnv{
		swtch:   NewSwitch(opPriv, logger, version, opPub, opID, eth),
		opID:    opID,
		opPub:   opPub,
		version: version,
		queried: queried,
	}
}

// operators returns an operator list containing this node, so CreateInstance can
// resolve our own ID once a message gets that far.
func (e *batchTestEnv) operators() []*spec.Operator {
	return []*spec.Operator{{ID: e.opID, PubKey: e.opPub}}
}

// foreignOperatorKey returns an encoded RSA public key belonging to no test node,
// so operator lookups by public key never resolve to it.
func foreignOperatorKey(t *testing.T) []byte {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	pub, err := spec_crypto.EncodeRSAPublicKey(&priv.PublicKey)
	require.NoError(t, err)
	return pub
}

func (e *batchTestEnv) resignMessage(owner common.Address, validatorPK []byte, proofOwners ...common.Address) *wire.ResignMessage {
	if len(proofOwners) == 0 {
		proofOwners = []common.Address{owner}
	}
	proofs := make([]*spec.SignedProof, 0, len(proofOwners))
	for _, proofOwner := range proofOwners {
		proofs = append(proofs, &spec.SignedProof{Proof: &spec.Proof{
			ValidatorPubKey: validatorPK,
			EncryptedShare:  bytesRepeat(0x01, 128),
			SharePubKey:     bytesRepeat(0x00, 48),
			Owner:           proofOwner,
		}, Signature: bytesRepeat(0x00, 256)})
	}
	return &wire.ResignMessage{
		Operators: e.operators(),
		Resign: &spec.Resign{
			ValidatorPubKey:       validatorPK,
			WithdrawalCredentials: eth1Creds(),
			Owner:                 owner,
			Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		Proofs: proofs,
	}
}

func (e *batchTestEnv) reshareMessage(owner common.Address, validatorPK []byte) *wire.ReshareMessage {
	return &wire.ReshareMessage{
		Reshare: &spec.Reshare{
			ValidatorPubKey:       validatorPK,
			OldOperators:          e.operators(),
			NewOperators:          e.operators(),
			OldT:                  3,
			NewT:                  3,
			WithdrawalCredentials: eth1Creds(),
			Owner:                 owner,
			Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		Proofs: []*spec.SignedProof{{Proof: &spec.Proof{
			ValidatorPubKey: validatorPK,
			EncryptedShare:  bytesRepeat(0x01, 128),
			SharePubKey:     bytesRepeat(0x00, 48),
			Owner:           owner,
		}, Signature: bytesRepeat(0x00, 256)}},
	}
}

// handle marshals data as the given transport type, signs it with a throwaway
// initiator key and drives HandleInstanceOperation.
func (e *batchTestEnv) handle(t *testing.T, msg wire.SSZMarshaller, msgType wire.TransportType, operationType string) ([][]byte, error) {
	t.Helper()
	data, err := msg.MarshalSSZ()
	require.NoError(t, err)

	var reqID [24]byte
	transport := &wire.Transport{Type: msgType, Identifier: reqID, Data: data, Version: e.version}
	tBytes, err := transport.MarshalSSZ()
	require.NoError(t, err)

	// Any initiator may send this — the operator authenticates the initiator's own
	// key, not an allow-list.
	initPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	initPub, err := spec_crypto.EncodeRSAPublicKey(&initPriv.PublicKey)
	require.NoError(t, err)
	initSig, err := spec_crypto.SignRSA(initPriv, tBytes)
	require.NoError(t, err)

	return e.swtch.HandleInstanceOperation(reqID, transport, initPub, initSig, operationType)
}

// TestResignBatchRejectsMessageWithDifferentOwner asserts a batch carrying two
// different owners is rejected outright, and that no ceremony runs for either
// message. Only the first message's owner authorised anything.
func TestResignBatchRejectsMessageWithDifferentOwner(t *testing.T) {
	env := newBatchTestEnv(t)

	signedResign := &wire.SignedResign{
		Messages: []*wire.ResignMessage{
			env.resignMessage(contractOwner, bytesRepeat(0xAA, 48)), // authorises the batch
			env.resignMessage(otherOwner, bytesRepeat(0xBB, 48)),    // never authorised
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedResign, wire.SignedResignMessageType, "resign")

	require.Error(t, err)
	require.ErrorContains(t, err, "is not the authorised owner")
	require.NotContains(t, err.Error(), "failed to run instance",
		"the batch must be rejected before any ceremony runs")
	require.Empty(t, env.swtch.Instances, "no instance may be created for either message")

	require.Contains(t, *env.queried, contractOwner, "message 0 owner authorised the batch")
	require.NotContains(t, *env.queried, otherOwner,
		"message 1's owner never authorised anything, so its message must not execute")
}

// TestResignBatchRejectsProofOwnerMismatch asserts that a message whose own owner
// is authorised but whose proofs name a different owner is still rejected.
func TestResignBatchRejectsProofOwnerMismatch(t *testing.T) {
	env := newBatchTestEnv(t)

	signedResign := &wire.SignedResign{
		Messages: []*wire.ResignMessage{
			env.resignMessage(contractOwner, bytesRepeat(0xAA, 48), otherOwner),
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedResign, wire.SignedResignMessageType, "resign")

	require.Error(t, err)
	require.ErrorContains(t, err, "proof 0 owner")
	require.ErrorContains(t, err, "is not the authorised owner")
	require.Empty(t, env.swtch.Instances)
}

// TestResignBatchAcceptsUniformOwner is the negative control: a batch whose
// messages all belong to the authorised owner must clear the authorisation stage
// and fail, if at all, only in ceremony execution.
func TestResignBatchAcceptsUniformOwner(t *testing.T) {
	env := newBatchTestEnv(t)

	signedResign := &wire.SignedResign{
		Messages: []*wire.ResignMessage{
			env.resignMessage(contractOwner, bytesRepeat(0xAA, 48)),
			env.resignMessage(contractOwner, bytesRepeat(0xBB, 48)),
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedResign, wire.SignedResignMessageType, "resign")

	require.Error(t, err, "the placeholder proofs still fail ceremony validation")
	require.NotContains(t, err.Error(), "is not the authorised owner",
		"a uniformly owned batch must not be rejected by the authorisation stage")
	require.ErrorContains(t, err, "failed to run instance")
}

// TestReshareBatchRejectsMessageWithDifferentOwner mirrors the resign case on the
// reshare branch.
func TestReshareBatchRejectsMessageWithDifferentOwner(t *testing.T) {
	env := newBatchTestEnv(t)

	signedReshare := &wire.SignedReshare{
		Messages: []*wire.ReshareMessage{
			env.reshareMessage(contractOwner, bytesRepeat(0xAA, 48)),
			env.reshareMessage(otherOwner, bytesRepeat(0xBB, 48)),
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

	require.Error(t, err)
	require.ErrorContains(t, err, "is not the authorised owner")
	require.NotContains(t, err.Error(), "failed to run instance",
		"the batch must be rejected before any ceremony runs")
	require.Empty(t, env.swtch.Instances)

	require.Contains(t, *env.queried, contractOwner)
	require.NotContains(t, *env.queried, otherOwner)
}

// TestInstanceOperationRejectsEmptyBatchAndProofs asserts empty message and proof
// lists — both valid SSZ — are rejected rather than indexed into.
func TestInstanceOperationRejectsEmptyBatchAndProofs(t *testing.T) {
	validatorPK := bytesRepeat(0xAA, 48)

	tests := []struct {
		name          string
		operationType string
		msgType       wire.TransportType
		message       func(e *batchTestEnv) wire.SSZMarshaller
		expectedErr   string
	}{
		{
			name:          "resign without messages",
			operationType: "resign",
			msgType:       wire.SignedResignMessageType,
			message: func(e *batchTestEnv) wire.SSZMarshaller {
				return &wire.SignedResign{Signature: bytesRepeat(0x00, 65)}
			},
			expectedErr: "no resign messages",
		},
		{
			name:          "reshare without messages",
			operationType: "reshare",
			msgType:       wire.SignedReshareMessageType,
			message: func(e *batchTestEnv) wire.SSZMarshaller {
				return &wire.SignedReshare{Signature: bytesRepeat(0x00, 65)}
			},
			expectedErr: "no reshare messages",
		},
		{
			name:          "resign message without proofs",
			operationType: "resign",
			msgType:       wire.SignedResignMessageType,
			message: func(e *batchTestEnv) wire.SSZMarshaller {
				msg := e.resignMessage(contractOwner, validatorPK)
				msg.Proofs = nil
				return &wire.SignedResign{
					Messages:  []*wire.ResignMessage{msg},
					Signature: bytesRepeat(0x00, 65),
				}
			},
			expectedErr: "message 0 has no proofs",
		},
		{
			name:          "reshare message without proofs",
			operationType: "reshare",
			msgType:       wire.SignedReshareMessageType,
			message: func(e *batchTestEnv) wire.SSZMarshaller {
				msg := e.reshareMessage(contractOwner, validatorPK)
				msg.Proofs = nil
				return &wire.SignedReshare{
					Messages:  []*wire.ReshareMessage{msg},
					Signature: bytesRepeat(0x00, 65),
				}
			},
			expectedErr: "message 0 has no proofs",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newBatchTestEnv(t)
			require.NotPanics(t, func() {
				_, err := env.handle(t, tc.message(env), tc.msgType, tc.operationType)
				require.ErrorContains(t, err, tc.expectedErr)
			})
			require.Empty(t, env.swtch.Instances)
		})
	}
}

// TestReshareRejectsStructurallyInvalidMessage asserts a reshare message is checked
// for structural validity even when this operator appears only among the new
// operators, so no instance is created for a fabricated message.
func TestReshareRejectsStructurallyInvalidMessage(t *testing.T) {
	env := newBatchTestEnv(t)
	validatorPK := bytesRepeat(0xAA, 48)

	// This operator is only among the new operators, so the old-operator validation
	// path never covers this message.
	oldOperators := []*spec.Operator{
		{ID: 30, PubKey: foreignOperatorKey(t)},
		{ID: 20, PubKey: foreignOperatorKey(t)}, // out of order
	}

	msg := &wire.ReshareMessage{
		Reshare: &spec.Reshare{
			ValidatorPubKey:       validatorPK,
			OldOperators:          oldOperators,
			NewOperators:          env.operators(),
			OldT:                  3,
			NewT:                  99, // not a valid threshold for the new set
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
	}

	signedReshare := &wire.SignedReshare{
		Messages:  []*wire.ReshareMessage{msg},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

	require.Error(t, err)
	require.ErrorContains(t, err, "old operators are not unique and ordered")
	require.Empty(t, env.swtch.Instances, "no instance may be created for a malformed message")
}

// TestMaskCeremonyErrorMasksAllErrors asserts the presented error is always the
// generic ceremony code while the original error stays available for logging.
func TestMaskCeremonyErrorMasksAllErrors(t *testing.T) {
	original := errors.New("internal ceremony detail")

	masked := maskCeremonyError(original)

	var sensitive *utils.SensitiveError
	require.ErrorAs(t, masked, &sensitive)
	require.Equal(t, string(wire.InitiatorErrorCodeCeremonyFailed), sensitive.PresentedErr)
	require.ErrorIs(t, masked, original, "the original error must remain available for logs")
	require.Equal(t, original.Error(), masked.Error())
}
