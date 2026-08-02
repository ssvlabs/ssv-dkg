package operator

// Regression test for the reshare share-recovery ordering.
//
// The invariant under test is the reshare twin of the one pinned on the resign path: a
// ceremony proof is validated against this operator's OWN key, and only then is the
// encrypted share it carries decrypted. Decrypting first — even discarding the result
// when validation later fails — turns the route into a chosen-ciphertext oracle.

import (
	"crypto/rsa"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// TestReshareValidatesProofBeforeDecryptingShare asserts the reshare path never decrypts a
// share whose proof does not validate against this operator's own key.
//
// There is no injectable decryption seam here — GetSecretShareFromProofs takes the
// operator's *rsa.PrivateKey directly — so the observation is made the other way round:
// the switch is built with NO private key at all. A decryption attempted before validation
// therefore dereferences a nil key and panics, which makes "did not panic" a statement
// about execution order rather than about the wording of an error. The switch's public key
// is set independently, so validation still has everything it needs to reject the proof.
func TestReshareValidatesProofBeforeDecryptingShare(t *testing.T) {
	const opID = uint64(1)
	validatorPK := bytesRepeat(0xAA, 48)

	opPub, err := spec_crypto.EncodeRSAPublicKey(&mustRSAKey(t).PublicKey)
	require.NoError(t, err)

	eth := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) { return nil, nil },
	}
	// No private key: any decryption on this switch is a hard, visible failure.
	s := NewSwitch(nil, zap.NewNop(), []byte("test.version"), opPub, opID, eth)

	// This operator IS among the old operators, so the branch that validates our proof
	// and decrypts our share is live. Old and new sets differ, as the spec requires.
	oldOperators := append([]*spec.Operator{{ID: opID, PubKey: opPub}}, foreignOperators(t, 2, 3, 4)...)
	proofs := make([]*spec.SignedProof, 0, len(oldOperators))
	for range oldOperators {
		proofs = append(proofs, &spec.SignedProof{Proof: &spec.Proof{
			ValidatorPubKey: validatorPK,
			EncryptedShare:  bytesRepeat(0x01, 128),
			SharePubKey:     blsSharePubKey(t),
			Owner:           contractOwner,
			// signed by nobody: verification against our own public key must reject it
		}, Signature: bytesRepeat(0x00, 256)})
	}

	msg := &wire.ReshareMessage{
		Reshare: &spec.Reshare{
			ValidatorPubKey:       validatorPK,
			OldOperators:          oldOperators,
			NewOperators:          foreignOperators(t, 5, 6, 7, 8),
			OldT:                  3,
			NewT:                  3,
			WithdrawalCredentials: eth1Creds(),
			Owner:                 contractOwner,
			Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		},
		Proofs: proofs,
	}

	// Precondition: the seam is live. Asserted on the exact call the ordering protects, so
	// this fails loudly if that call ever stops being nil-hostile, rather than letting the
	// test below silently stop proving anything.
	require.Panics(t, func() {
		_, _ = crypto.GetSecretShareFromProofs(msg.Proofs[0], nil, opID)
	}, "share decryption must be nil-hostile for this test to observe anything")

	var recoverErr error
	require.NotPanics(t, func() {
		_, _, recoverErr = s.getPublicCommitsAndSecretShare(msg)
	}, "the share must not be decrypted before its proof is validated")

	require.Error(t, recoverErr)
	require.ErrorIs(t, recoverErr, rsa.ErrVerification,
		"the request must stop at proof verification")
	require.NotContains(t, recoverErr.Error(), "decrypt")
}
