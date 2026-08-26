package dkg

// Regression tests for LocalOwner.Resign proof validation.
//
// The invariant under test: a resign ceremony proof is validated against this
// operator's OWN RSA key, never against a key supplied in the message, and the
// encrypted share is only decrypted after that validation succeeds.

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"testing"

	kyber_bls "github.com/drand/kyber-bls12381"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// newTestOwner builds a LocalOwner exactly as the operator server would: it
// decrypts ceremony shares with the operator's own RSA private key. The returned
// counter records how many times the share decryption ran, so tests can assert on
// the behaviour itself rather than on the wording of the resulting error.
func newTestOwner(t *testing.T, id uint64) (*LocalOwner, *rsa.PrivateKey, *int) {
	t.Helper()
	pv, _, err := spec_crypto.GenerateRSAKeys()
	require.NoError(t, err)
	logger, _ := zap.NewDevelopment()
	decrypts := new(int)
	o := &LocalOwner{
		Logger:    logger.With(zap.Uint64("operator_id", id)),
		ID:        id,
		Suite:     kyber_bls.NewBLS12381Suite(),
		exchanges: make(map[uint64]*wire.Exchange),
		signer:    crypto.RSASigner(pv),
		decryptFunc: func(ct []byte) ([]byte, error) {
			*decrypts++
			return spec_crypto.Decrypt(pv, ct)
		},
		OperatorSecretKey: pv,
		done:              make(chan struct{}, 1),
		startedDKG:        make(chan struct{}, 1),
	}
	return o, pv, decrypts
}

func encodePub(t *testing.T, pk *rsa.PublicKey) []byte {
	t.Helper()
	b, err := spec_crypto.EncodeRSAPublicKey(pk)
	require.NoError(t, err)
	return b
}

// signProof RSA-signs a Proof with the given key, producing a SignedProof that
// validates against that key's public half.
func signProof(t *testing.T, sk *rsa.PrivateKey, p *spec.Proof) *spec.SignedProof {
	t.Helper()
	root, err := p.HashTreeRoot()
	require.NoError(t, err)
	sig, err := spec_crypto.SignRSA(sk, root[:])
	require.NoError(t, err)
	return &spec.SignedProof{Proof: p, Signature: sig}
}

func validWithdrawalCreds() []byte {
	creds := make([]byte, 32)
	creds[0] = 1 // ETH1WithdrawalPrefix
	return creds
}

// TestResignRejectsProofNotSignedByThisOperator asserts that a proof signed by a
// key other than the operator's own is rejected, even when the message lists this
// operator's ID twice with the foreign key first. Validation must fail before the
// encrypted share is decrypted.
func TestResignRejectsProofNotSignedByThisOperator(t *testing.T) {
	opID := uint64(3)
	op, opPriv, decrypts := newTestOwner(t, opID)

	// A throwaway RSA keypair that is not this operator's key.
	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)

	otherAddr := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	validatorPK := make([]byte, 48)
	for i := range validatorPK {
		validatorPK[i] = 0xAB
	}

	// A chosen ciphertext, encrypted under the operator's public key so PKCS#1 v1.5
	// padding validates. Its plaintext is not a BLS secret key.
	chosenCiphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &opPriv.PublicKey, []byte("not-a-bls-key"))
	require.NoError(t, err)

	proof := &spec.Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  chosenCiphertext,
		SharePubKey:     make([]byte, 48),
		Owner:           otherAddr,
	}
	signed := signProof(t, otherPriv, proof) // signed with the foreign key

	resign := &spec.Resign{
		ValidatorPubKey:       validatorPK,
		Fork:                  [4]byte{0, 0, 0, 0},
		WithdrawalCredentials: validWithdrawalCreds(),
		Owner:                 otherAddr,
		Nonce:                 0,
		Amount:                32000000000, // 32 ETH, MIN_ACTIVATION_BALANCE
	}

	// The operator's ID appears TWICE, the foreign key first.
	msg := &wire.ResignMessage{
		Operators: []*spec.Operator{
			{ID: opID, PubKey: encodePub(t, &otherPriv.PublicKey)}, // entry carrying a different key
			{ID: opID, PubKey: encodePub(t, &opPriv.PublicKey)},    // genuine
		},
		Resign: resign,
		Proofs: []*spec.SignedProof{signed, signed},
	}

	// Documents why the operator entry in the message cannot be trusted: validated
	// against the message-supplied key, the proof passes.
	err = spec.ValidateResignMessage(resign, spec.GetOperator(msg.Operators, opID), msg.Proofs[0])
	require.NoError(t, err, "the message-supplied key accepts the proof")

	// Validated against the operator's own key — the key the fixed code uses — it fails.
	selfOp := &spec.Operator{ID: opID, PubKey: encodePub(t, &opPriv.PublicKey)}
	err = spec.ValidateResignMessage(resign, selfOp, msg.Proofs[0])
	require.Error(t, err, "validating against the operator's own key rejects the proof")

	// End to end: Resign rejects at validation and never decrypts the share.
	reqID := [24]byte{1, 2, 3}
	_, err = op.Resign(reqID, msg)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to validate resign message")
	require.ErrorContains(t, err, "crypto/rsa: verification error")
	require.ErrorIs(t, err, rsa.ErrVerification)
	require.NotContains(t, err.Error(), "BLS secret key",
		"validation must stop the request before the share is parsed")
	require.NotContains(t, err.Error(), "decrypt",
		"validation must stop the request before the share is decrypted")
	// The assertions above only certify wording. This one certifies the behaviour:
	// the chosen ciphertext was never fed to the operator's private key at all.
	require.Zero(t, *decrypts,
		"the share must not be decrypted when validation rejects the proof")
}

// TestResignErrorsAreIndistinguishableAcrossCiphertexts asserts that two resign
// requests differing only in their encrypted share produce the same error, so the
// response carries no information about the ciphertext.
func TestResignErrorsAreIndistinguishableAcrossCiphertexts(t *testing.T) {
	opID := uint64(3)
	op, opPriv, decrypts := newTestOwner(t, opID)

	otherPriv, err := rsa.GenerateKey(rand.Reader, 2048)
	require.NoError(t, err)
	otherAddr := common.HexToAddress("0x00000000000000000000000000000000deadbeef")
	validatorPK := make([]byte, 48)

	buildResign := func(ciphertext []byte) *wire.ResignMessage {
		proof := &spec.Proof{
			ValidatorPubKey: validatorPK,
			EncryptedShare:  ciphertext,
			SharePubKey:     make([]byte, 48),
			Owner:           otherAddr,
		}
		signed := signProof(t, otherPriv, proof)
		return &wire.ResignMessage{
			Operators: []*spec.Operator{{ID: opID, PubKey: encodePub(t, &otherPriv.PublicKey)}},
			Resign: &spec.Resign{
				ValidatorPubKey:       validatorPK,
				WithdrawalCredentials: validWithdrawalCreds(),
				Owner:                 otherAddr,
				Amount:                32000000000,
			},
			Proofs: []*spec.SignedProof{signed},
		}
	}

	// Well-formed PKCS#1 v1.5 padding.
	validPadding, err := rsa.EncryptPKCS1v15(rand.Reader, &opPriv.PublicKey, []byte("x"))
	require.NoError(t, err)
	_, errValid := op.Resign([24]byte{}, buildResign(validPadding))
	require.Error(t, errValid)

	// Malformed padding.
	invalidPadding := make([]byte, 256)
	for i := range invalidPadding {
		invalidPadding[i] = 0xFF
	}
	_, errInvalid := op.Resign([24]byte{}, buildResign(invalidPadding))
	require.Error(t, errInvalid)

	// Both stop at validation, so neither reaches decryption.
	require.ErrorContains(t, errValid, "failed to validate resign message")
	require.ErrorContains(t, errInvalid, "failed to validate resign message")
	require.False(t, errors.Is(errValid, rsa.ErrDecryption))
	require.False(t, errors.Is(errInvalid, rsa.ErrDecryption))

	// The two ciphertexts are indistinguishable from the error alone.
	require.Equal(t, errValid.Error(), errInvalid.Error(),
		"errors must not vary with the supplied ciphertext")

	// Indistinguishable errors would still leak through a timing side channel if the
	// ciphertexts reached the private key at all. Neither did.
	require.Zero(t, *decrypts,
		"neither ciphertext may be decrypted when validation rejects the proof")
}

// TestResignRejectsProofOwnerMismatch asserts the ceremony-level check that the
// resign owner matches the proof owner. The proof is signed by this operator's own
// key, so only the owner mismatch can reject it.
func TestResignRejectsProofOwnerMismatch(t *testing.T) {
	opID := uint64(3)
	op, opPriv, _ := newTestOwner(t, opID)

	proofOwner := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	resignOwner := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	validatorPK := make([]byte, 48)
	for i := range validatorPK {
		validatorPK[i] = 0xCD
	}

	proof := &spec.Proof{
		ValidatorPubKey: validatorPK,
		EncryptedShare:  make([]byte, 256),
		SharePubKey:     make([]byte, 48),
		Owner:           proofOwner,
	}
	signed := signProof(t, opPriv, proof) // genuine: signed with the operator's own key

	msg := &wire.ResignMessage{
		Operators: []*spec.Operator{{ID: opID, PubKey: encodePub(t, &opPriv.PublicKey)}},
		Resign: &spec.Resign{
			ValidatorPubKey:       validatorPK,
			WithdrawalCredentials: validWithdrawalCreds(),
			Owner:                 resignOwner,
			Amount:                32000000000,
		},
		Proofs: []*spec.SignedProof{signed},
	}

	_, err := op.Resign([24]byte{}, msg)
	require.Error(t, err)
	require.ErrorContains(t, err, "failed to validate resign message")
	require.ErrorContains(t, err, "invalid owner address")
}

// TestResignRejectsProofsLenMismatch asserts the message is rejected when the proofs
// and operators lists disagree, rather than indexing out of range.
func TestResignRejectsProofsLenMismatch(t *testing.T) {
	opID := uint64(3)
	op, opPriv, _ := newTestOwner(t, opID)

	tests := []struct {
		name   string
		proofs []*spec.SignedProof
	}{
		{name: "no proofs", proofs: nil},
		{
			name:   "fewer proofs than operators",
			proofs: []*spec.SignedProof{{Proof: &spec.Proof{}, Signature: make([]byte, 256)}},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			msg := &wire.ResignMessage{
				Operators: []*spec.Operator{
					{ID: opID, PubKey: encodePub(t, &opPriv.PublicKey)},
					{ID: opID + 1, PubKey: encodePub(t, &opPriv.PublicKey)},
				},
				Resign: &spec.Resign{
					ValidatorPubKey:       make([]byte, 48),
					WithdrawalCredentials: validWithdrawalCreds(),
					Owner:                 common.HexToAddress("0x00000000000000000000000000000000000000aa"),
					Amount:                32000000000,
				},
				Proofs: tc.proofs,
			}

			_, err := op.Resign([24]byte{}, msg)
			require.ErrorContains(t, err, "wrong proofs len at resign message")
		})
	}
}
