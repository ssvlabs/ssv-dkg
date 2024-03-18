package crypto

import (
	"crypto/rand"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/drand/kyber/share"
	drand_dkg "github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/herumi/bls-eth-go-binary/bls"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

const (
	// b64 encrypted key length is 256
	EncryptedKeyLength = 256
	// Signature len
	SignatureLength = 256
	// MaxEffectiveBalanceInGwei is the max effective balance
	MaxEffectiveBalanceInGwei phase0.Gwei = 32000000000
)

func init() {
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)
}

// NewID generates a random ID from 2 random concat UUIDs
func NewID() [24]byte {
	var id [24]byte
	b := uuid.New()
	copy(id[:12], b[:])
	b = uuid.New()
	copy(id[12:], b[:])
	return id
}

// ResultToShareSecretKey converts a private share at kyber DKG result to github.com/herumi/bls-eth-go-binary/bls private key
func ResultToShareSecretKey(result *drand_dkg.DistKeyShare) (*bls.SecretKey, error) {
	privShare := result.PriShare()
	bytsSk, err := privShare.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

// ResultsToValidatorPK converts a public polynomial at kyber DKG result to github.com/herumi/bls-eth-go-binary/bls public key
func ResultToValidatorPK(result *drand_dkg.DistKeyShare, suite drand_dkg.Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), result.Commitments())
	bytsPK, err := exp.Commit().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("could not marshal share %w", err)
	}
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(bytsPK); err != nil {
		return nil, err
	}
	return pk, nil
}

// VerifyOwnerNonceSignature check that owner + nonce correctly signed
func VerifyOwnerNonceSignature(sig []byte, owner common.Address, pubKey []byte, nonce uint16) error {
	data := fmt.Sprintf("%s:%d", owner.String(), nonce)
	hash := eth_crypto.Keccak256([]byte(data))

	sign := &bls.Sign{}
	if err := sign.Deserialize(sig); err != nil {
		return fmt.Errorf("failed to deserialize signature: %w", err)
	}

	pk := &bls.PublicKey{}
	if err := pk.Deserialize(pubKey); err != nil {
		return fmt.Errorf("failed to deserialize public key: %w", err)
	}

	if res := sign.VerifyByte(pk, hash); !res {
		return ErrInvalidSignature
	}

	return nil
}

// RecoverValidatorPublicKey recovers a BLS master public key (validator pub key) from provided partial pub keys
func RecoverValidatorPublicKey(ids []uint64, sharePks []*bls.PublicKey) (*bls.PublicKey, error) {
	if len(ids) != len(sharePks) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	validatorRecoveredPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *sharePks[i])
	}
	if err := validatorRecoveredPK.Recover(pkVec, idVec); err != nil {
		return nil, err
	}
	return &validatorRecoveredPK, nil
}

// RecoverBLSSignature recovers a BLS master signature from T-threshold partial signatures
func RecoverBLSSignature(ids []uint64, partialSigs []*bls.Sign) (*bls.Sign, error) {
	if len(ids) != len(partialSigs) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	reconstructed := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		sigVec = append(sigVec, *partialSigs[i])
	}
	if err := reconstructed.Recover(sigVec, idVec); err != nil {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	return &reconstructed, nil
}

func VerifyPartialSigs(sigs []*bls.Sign, pubs []*bls.PublicKey, data []byte) error {
	for i, sig := range sigs {
		if !sig.VerifyByte(pubs[i], data) {
			return fmt.Errorf("partial signature is invalid  #%d: sig %x root %x", i, sig.Serialize(), data)
		}
	}
	return nil
}

// Encrypt with RSA public key private DKG share key
func Encrypt(pub *rsa.PublicKey, msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, pub, msg)
}
