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
	"fmt"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
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
	opPriv  *rsa.PrivateKey
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
		opPriv:  opPriv,
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

// mustRSAKey returns a fresh RSA private key.
func mustRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	return priv
}

// foreignOperatorKey returns an encoded RSA public key belonging to no test node,
// so operator lookups by public key never resolve to it.
func foreignOperatorKey(t *testing.T) []byte {
	t.Helper()
	pub, err := spec_crypto.EncodeRSAPublicKey(&mustRSAKey(t).PublicKey)
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

func (e *batchTestEnv) reshareMessage(owner common.Address, validatorPK []byte, proofOwners ...common.Address) *wire.ReshareMessage {
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
		Proofs: proofs,
	}
}

// foreignOperators returns an ordered operator list whose keys belong to no test node.
func foreignOperators(t *testing.T, ids ...uint64) []*spec.Operator {
	t.Helper()
	ops := make([]*spec.Operator, 0, len(ids))
	for _, id := range ids {
		ops = append(ops, &spec.Operator{ID: id, PubKey: foreignOperatorKey(t)})
	}
	return ops
}

// blsSharePubKey returns a well-formed BLS public key, so proofs carrying it survive the
// commitment recovery that precedes any ownership check.
func blsSharePubKey(t *testing.T) []byte {
	t.Helper()
	sk := &bls.SecretKey{}
	sk.SetByCSPRNG()
	return sk.GetPublicKey().Serialize()
}

// validResignMessage builds a resign message that runs to completion: the proof is signed
// by this node's own RSA key and its encrypted share really is a BLS secret key encrypted
// to this node. Tests that must observe whether a ceremony ran need a message that can
// actually run — a message rejected on its own merits makes "no instance was created"
// true whether or not the guard under test exists.
func (e *batchTestEnv) validResignMessage(t *testing.T, owner common.Address, validatorPK []byte) *wire.ResignMessage {
	t.Helper()
	share := &bls.SecretKey{}
	share.SetByCSPRNG()
	encryptedShare, err := spec_crypto.Encrypt(&e.opPriv.PublicKey, []byte(share.SerializeToHexStr()))
	require.NoError(t, err)

	proof := &spec.Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  encryptedShare,
		SharePubKey:     share.GetPublicKey().Serialize(),
		Owner:           owner,
	}
	root, err := proof.HashTreeRoot()
	require.NoError(t, err)
	signature, err := spec_crypto.SignRSA(e.opPriv, root[:])
	require.NoError(t, err)

	return &wire.ResignMessage{
		Operators: e.operators(),
		Resign: &spec.Resign{
			ValidatorPubKey:       validatorPK,
			Fork:                  [4]byte{0, 0, 0, 0}, // mainnet
			WithdrawalCredentials: eth1Creds(),
			Owner:                 owner,
			Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		Proofs: []*spec.SignedProof{{Proof: proof, Signature: signature}},
	}
}

// validReshareMessage builds a reshare message that runs to completion with this node
// among the NEW operators only. On that path getPublicCommitsAndSecretShare never enters
// its old-operator branch, so no proof of ours is validated and no share of ours is
// decrypted — only the membership-independent structural checks stand between the message
// and a created instance. That is the path the disclosed fix hardened, and it lets a test
// observe whether a guard ran by asking whether an instance exists.
func (e *batchTestEnv) validReshareMessage(t *testing.T, owner common.Address, validatorPK []byte) *wire.ReshareMessage {
	t.Helper()
	oldOperators := foreignOperators(t, 10, 20, 30, 40)
	newOperators := append([]*spec.Operator{{ID: e.opID, PubKey: e.opPub}}, foreignOperators(t, 2, 3, 4)...)

	proofs := make([]*spec.SignedProof, 0, len(oldOperators))
	for range oldOperators {
		proofs = append(proofs, &spec.SignedProof{Proof: &spec.Proof{
			ValidatorPubKey: validatorPK,
			EncryptedShare:  bytesRepeat(0x01, 128),
			SharePubKey:     blsSharePubKey(t),
			Owner:           owner,
		}, Signature: bytesRepeat(0x00, 256)})
	}

	return &wire.ReshareMessage{
		Reshare: &spec.Reshare{
			ValidatorPubKey:       validatorPK,
			OldOperators:          oldOperators,
			NewOperators:          newOperators,
			OldT:                  3,
			NewT:                  3,
			WithdrawalCredentials: eth1Creds(),
			Owner:                 owner,
			Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		Proofs: proofs,
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

// TestResignBatchRejectsMessageOwnerWhenProofsLookAuthorised asserts that a message
// whose own owner is not the authorised one is rejected even when all of its proofs name
// the authorised owner, so the proof loop cannot stand in for the message-owner check.
//
// Message 0 is a ceremony that would run to completion. That is what gives this test
// teeth: the batch must be rejected before ANY message executes, so the absence of an
// instance is evidence the guard ran, not an accident of a fixture that could never run.
func TestResignBatchRejectsMessageOwnerWhenProofsLookAuthorised(t *testing.T) {
	env := newBatchTestEnv(t)

	signedResign := &wire.SignedResign{
		Messages: []*wire.ResignMessage{
			env.validResignMessage(t, contractOwner, bytesRepeat(0xAA, 48)), // would complete
			// message owner is not the authorised owner, but its proofs claim to be
			env.resignMessage(otherOwner, bytesRepeat(0xBB, 48), contractOwner),
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedResign, wire.SignedResignMessageType, "resign")

	require.Error(t, err)
	require.Empty(t, env.swtch.Instances,
		"the batch must be rejected before any ceremony runs, including the one that would succeed")
	require.ErrorContains(t, err, "message 1 owner")
	require.ErrorContains(t, err, "is not the authorised owner")
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

// TestReshareBatchRejectsMessageOwnerWhenProofsLookAuthorised is the reshare twin of the
// resign case: message 0 would run to completion, so an instance exists if and only if
// the batch was allowed to execute.
func TestReshareBatchRejectsMessageOwnerWhenProofsLookAuthorised(t *testing.T) {
	env := newBatchTestEnv(t)

	signedReshare := &wire.SignedReshare{
		Messages: []*wire.ReshareMessage{
			env.validReshareMessage(t, contractOwner, bytesRepeat(0xAA, 48)), // would complete
			env.reshareMessage(otherOwner, bytesRepeat(0xBB, 48), contractOwner),
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

	require.Error(t, err)
	require.Empty(t, env.swtch.Instances,
		"the batch must be rejected before any ceremony runs, including the one that would succeed")
	require.ErrorContains(t, err, "message 1 owner")
	require.ErrorContains(t, err, "is not the authorised owner")
}

// TestReshareBatchRejectsProofOwnerMismatch asserts that a reshare message whose own owner
// is authorised but whose proof names a different owner is rejected.
//
// The message is otherwise a ceremony that completes, and this node appears only among the
// NEW operators — the path on which no proof of ours is ever validated. So if the batch
// proof-owner loop were removed, nothing downstream would object: the ceremony would run
// and return no error at all. Both the error and the empty instance map are therefore
// evidence that the loop ran.
func TestReshareBatchRejectsProofOwnerMismatch(t *testing.T) {
	env := newBatchTestEnv(t)

	msg := env.validReshareMessage(t, contractOwner, bytesRepeat(0xAA, 48))
	msg.Proofs[0].Proof.Owner = otherOwner

	signedReshare := &wire.SignedReshare{
		Messages:  []*wire.ReshareMessage{msg},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

	require.Error(t, err, "a proof naming another owner must stop the ceremony")
	require.Empty(t, env.swtch.Instances, "no instance may be created for a rejected message")
	require.ErrorContains(t, err, "proof 0 owner")
	require.ErrorContains(t, err, "is not the authorised owner")
}

// TestReshareOwnerAnchoredToReshareMessage asserts the owner a reshare batch is authorised
// against comes from the reshare message itself, never from a proof the message carries.
//
// The fixture separates the two: the message names an EOA that authorises nothing, while
// its proof names the contract owner that rubber-stamps any signature. The pin is the
// record of which address the EIP-1271 check actually queried — an attacker who could move
// the anchor into the proofs could authorise a batch with an owner of their choosing.
func TestReshareOwnerAnchoredToReshareMessage(t *testing.T) {
	env := newBatchTestEnv(t)

	signedReshare := &wire.SignedReshare{
		Messages: []*wire.ReshareMessage{
			env.reshareMessage(otherOwner, bytesRepeat(0xAA, 48), contractOwner),
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

	require.Error(t, err)
	require.Contains(t, *env.queried, otherOwner,
		"the signature must be verified against the owner named by the reshare message")
	require.NotContains(t, *env.queried, contractOwner,
		"an owner named only by a proof must never be asked to authorise the batch")
	require.ErrorContains(t, err, "failed to verify signed message by owner")
	require.Empty(t, env.swtch.Instances)
}

// TestResignBatchUsesEachMessageOperatorSet asserts every message in a batch is run
// against its OWN operator set, so one message cannot borrow another's membership.
//
// Message 1 keeps this node's operator ID but carries a foreign public key for it, and is
// otherwise a valid ceremony signed by this node's real key. Sourcing the operator set
// from message 0 would resolve membership from the wrong message and let message 1 run to
// completion on its own proof, so the pin is the instance count, not the error text.
func TestResignBatchUsesEachMessageOperatorSet(t *testing.T) {
	env := newBatchTestEnv(t)

	foreign := env.validResignMessage(t, contractOwner, bytesRepeat(0xBB, 48))
	foreign.Operators = []*spec.Operator{{ID: env.opID, PubKey: foreignOperatorKey(t)}}

	signedResign := &wire.SignedResign{
		Messages: []*wire.ResignMessage{
			env.validResignMessage(t, contractOwner, bytesRepeat(0xAA, 48)),
			foreign,
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedResign, wire.SignedResignMessageType, "resign")

	require.Error(t, err, "a message listing an operator set this node is not in must be rejected")
	require.Len(t, env.swtch.Instances, 1,
		"only the first message may create an instance; the second is not addressed to this node")
	require.ErrorContains(t, err, "wrong operator")
}

// TestReshareBatchUsesEachMessageOperatorSet is the reshare twin: message 1's old and new
// operator sets both exclude this node, so it must be rejected on membership even though
// message 0 named a set this node belongs to.
func TestReshareBatchUsesEachMessageOperatorSet(t *testing.T) {
	env := newBatchTestEnv(t)

	foreign := env.validReshareMessage(t, contractOwner, bytesRepeat(0xBB, 48))
	foreign.Reshare.NewOperators = foreignOperators(t, 5, 6, 7, 8)

	signedReshare := &wire.SignedReshare{
		Messages: []*wire.ReshareMessage{
			env.validReshareMessage(t, contractOwner, bytesRepeat(0xAA, 48)),
			foreign,
		},
		Signature: bytesRepeat(0x00, 65),
	}

	_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

	require.Error(t, err, "a message whose operator sets exclude this node must be rejected")
	require.Len(t, env.swtch.Instances, 1,
		"only the first message may create an instance; the second is not addressed to this node")
	require.ErrorContains(t, err, "wrong operator")
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

// TestReshareRejectsStructurallyInvalidMessage asserts every structural check on a reshare
// message runs even when this operator appears only among the NEW operators — the path on
// which none of the old-operator validation covers the message.
//
// One row per predicate, each breaking exactly one field and leaving every other field
// valid. That matters: a fixture that breaks two fields at once only ever proves the first
// check reached, and silently leaves the rest unguarded. Each row's base message would run
// to completion, so an absent error is itself a failure signal.
func TestReshareRejectsStructurallyInvalidMessage(t *testing.T) {
	validatorPK := bytesRepeat(0xAA, 48)

	tests := []struct {
		name        string
		breakField  func(r *spec.Reshare)
		expectedErr string
	}{
		{
			name: "old operators out of order",
			breakField: func(r *spec.Reshare) {
				r.OldOperators[0], r.OldOperators[1] = r.OldOperators[1], r.OldOperators[0]
			},
			expectedErr: "old operators are not unique and ordered",
		},
		{
			name: "new operators out of order",
			breakField: func(r *spec.Reshare) {
				r.NewOperators[0], r.NewOperators[1] = r.NewOperators[1], r.NewOperators[0]
			},
			expectedErr: "new operators are not unique and ordered",
		},
		{
			name:        "old threshold not valid for the old set",
			breakField:  func(r *spec.Reshare) { r.OldT = 99 },
			expectedErr: "old threshold set is invalid",
		},
		{
			name:        "new threshold not valid for the new set",
			breakField:  func(r *spec.Reshare) { r.NewT = 99 },
			expectedErr: "new threshold set is invalid",
		},
		{
			name:        "amount below the activation balance",
			breakField:  func(r *spec.Reshare) { r.Amount = 1 },
			expectedErr: "amount should be in range between 32 ETH and 2048 ETH",
		},
		{
			name:        "withdrawal credentials with an unknown prefix",
			breakField:  func(r *spec.Reshare) { r.WithdrawalCredentials[0] = 0xFF },
			expectedErr: "invalid withdrawal credentials",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newBatchTestEnv(t)
			msg := env.validReshareMessage(t, contractOwner, validatorPK)
			tc.breakField(msg.Reshare)

			signedReshare := &wire.SignedReshare{
				Messages:  []*wire.ReshareMessage{msg},
				Signature: bytesRepeat(0x00, 65),
			}

			_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")

			require.Error(t, err, "a message failing this check must not run")
			require.Empty(t, env.swtch.Instances, "no instance may be created for a malformed message")
			require.ErrorContains(t, err, tc.expectedErr)
		})
	}
}

// TestReshareRejectsProofsLenMismatch asserts a reshare message is rejected when its
// proofs and old-operator lists disagree, rather than being indexed into. It is the twin
// of TestResignRejectsProofsLenMismatch, which covers the resign side of the same guard.
//
// The surplus case is the sharp one: recovering the public commitments walks the proofs
// and indexes the old-operator list in step, so an extra proof reads past the end of it.
func TestReshareRejectsProofsLenMismatch(t *testing.T) {
	validatorPK := bytesRepeat(0xAA, 48)

	tests := []struct {
		name       string
		fixProofs  func(msg *wire.ReshareMessage)
		expectedIn string
	}{
		{
			name:       "fewer proofs than old operators",
			fixProofs:  func(msg *wire.ReshareMessage) { msg.Proofs = msg.Proofs[:len(msg.Proofs)-1] },
			expectedIn: "expected 4, got 3",
		},
		{
			name:       "more proofs than old operators",
			fixProofs:  func(msg *wire.ReshareMessage) { msg.Proofs = append(msg.Proofs, msg.Proofs[0]) },
			expectedIn: "expected 4, got 5",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			env := newBatchTestEnv(t)
			msg := env.validReshareMessage(t, contractOwner, validatorPK)
			tc.fixProofs(msg)

			signedReshare := &wire.SignedReshare{
				Messages:  []*wire.ReshareMessage{msg},
				Signature: bytesRepeat(0x00, 65),
			}

			require.NotPanics(t, func() {
				_, err := env.handle(t, signedReshare, wire.SignedReshareMessageType, "reshare")
				require.Error(t, err)
				require.ErrorContains(t, err, "wrong proofs len at reshare message")
				require.ErrorContains(t, err, tc.expectedIn)
			}, "a proofs/operators length mismatch must be rejected, not indexed into")
			require.Empty(t, env.swtch.Instances)
		})
	}
}

// TestCeremonyResponseErrorMasksEverythingExceptVersionMismatch enumerates the error
// classes a ceremony operation can return and asserts exactly one of them — a version
// mismatch — reaches the initiator intact.
//
// The route-level tests cannot bound this on their own: they exercise three concrete
// failures, so a carve-out widened to a class none of them produces would ship green. The
// decryption rows below are the ones that matter most — letting an rsa.ErrDecryption
// through unmasked is precisely the chosen-ciphertext oracle the masking exists to close.
func TestCeremonyResponseErrorMasksEverythingExceptVersionMismatch(t *testing.T) {
	versionMismatch := fmt.Errorf("%w: remote a local b", ErrVersionMismatch)

	tests := []struct {
		name     string
		err      error
		verbatim bool
	}{
		{name: "version mismatch", err: versionMismatch, verbatim: true},
		{name: "version mismatch wrapped by a caller", err: fmt.Errorf("resign: %w", versionMismatch), verbatim: true},

		{name: "share decryption failure", err: rsa.ErrDecryption},
		{name: "wrapped share decryption failure", err: fmt.Errorf("failed to decrypt encrypted share: %w", rsa.ErrDecryption)},
		{name: "signature verification failure", err: rsa.ErrVerification},
		{name: "initiator signature invalid", err: fmt.Errorf("resign: initiator signature isn't valid: %w", rsa.ErrVerification)},
		{name: "missing instance", err: utils.ErrMissingInstance},
		{name: "instance already exists", err: utils.ErrAlreadyExists},
		{name: "max instances reached", err: utils.ErrMaxInstances},
		{name: "owner signature not verified", err: fmt.Errorf("failed to verify signed message by owner: %w", rsa.ErrVerification)},
		{name: "unauthorised message owner", err: fmt.Errorf("resign: message 0 owner aa is not the authorised owner bb")},
		{name: "ceremony execution failure", err: fmt.Errorf("resign: failed to run instance: %w", errors.New("inner detail"))},
		{name: "empty batch", err: fmt.Errorf("resign: no resign messages")},
		{name: "unknown operation type", err: fmt.Errorf("unknown operation type: %s", "resign")},
		{name: "arbitrary ceremony detail", err: errors.New("some arbitrary ceremony detail")},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			respErr := fmt.Errorf("operator 1, failed to resign, err: %w", tc.err)

			got := ceremonyResponseError(tc.err, respErr)

			var sensitive *utils.SensitiveError
			if tc.verbatim {
				require.False(t, errors.As(got, &sensitive), "this class must not be masked")
				require.Equal(t, tc.err, got, "the error must reach the initiator unchanged")
				return
			}
			require.ErrorAs(t, got, &sensitive, "this class must be masked")
			require.Equal(t, string(wire.InitiatorErrorCodeCeremonyFailed), sensitive.PresentedErr)
			require.ErrorIs(t, got, tc.err, "the original error must remain available for logs")
		})
	}
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
