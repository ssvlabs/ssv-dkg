package crypto

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	drand_dkg "github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

const (
	// b64 encrypted key length is 256
	EncryptedKeyLength = 256
	// Signature len
	SignatureLength = 256
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

// KyberShareToBLSKey converts a kyber private share to github.com/herumi/bls-eth-go-binary/bls private key
func KyberShareToBLSKey(privShare *share.PriShare) (*bls.SecretKey, error) {
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
		return nil, fmt.Errorf("error recovering validator pub key from shares")
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

// ReconstructSignatures receives a map of user indexes and serialized bls.Sign.
// It then reconstructs the original threshold signature using lagrange interpolation
func ReconstructSignatures(ids []uint64, signatures [][]byte) (*bls.Sign, error) {
	if len(ids) != len(signatures) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	reconstructedSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", index))
		if err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		blsSig := bls.Sign{}

		err = blsSig.Deserialize(signatures[i])
		if err != nil {
			return nil, err
		}
		sigVec = append(sigVec, blsSig)
	}
	err := reconstructedSig.Recover(sigVec, idVec)
	return &reconstructedSig, err
}

// VerifyReconstructedSignature checks a reconstructed msg master signature against validator public key
func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey, msg []byte) error {
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(validatorPubKey); err != nil {
		return fmt.Errorf("could not deserialize validator pk %w", err)
	}
	// verify reconstructed sig
	if res := sig.VerifyByte(pk, msg); !res {
		return errors.New("could not reconstruct a valid signature")
	}
	return nil
}

func GetSecretShareFromSharesData(keyshares, initiatorPublicKey, ceremonySigs []byte, oldOperators []*wire.Operator, opPrivateKey *rsa.PrivateKey, operatorID uint64) (*share.PriShare, error) {
	suite := kyber_bls12381.NewBLS12381Suite()
	secret, position, err := checkKeySharesSlice(keyshares, oldOperators, operatorID, opPrivateKey)
	if err != nil {
		return nil, err
	}
	var kyberPrivShare *share.PriShare
	// Check operator signature
	initiatorPubKey, err := ParseRSAPublicKey(initiatorPublicKey)
	if err != nil {
		return nil, err
	}
	encInitPub, err := EncodeRSAPublicKey(initiatorPubKey)
	if err != nil {
		return nil, err
	}
	sigs := utils.SplitBytes(ceremonySigs, SignatureLength)
	serialized := secret.Serialize()
	dataToVerify := make([]byte, len(serialized)+len(encInitPub))
	copy(dataToVerify[:len(serialized)], serialized)
	copy(dataToVerify[len(serialized):], encInitPub)
	err = VerifyRSA(&opPrivateKey.PublicKey, dataToVerify, sigs[position])
	if err != nil {
		return nil, fmt.Errorf("cant verify initiator public key")
	}
	v := suite.G1().Scalar().SetBytes(serialized)
	kyberPrivShare = &share.PriShare{
		I: int(operatorID - 1),
		V: v,
	}
	return kyberPrivShare, nil
}

func checkKeySharesSlice(keyShares []byte, oldOperators []*wire.Operator, operatorID uint64, opPrivateKey *rsa.PrivateKey) (*bls.SecretKey, int, error) {
	pubKeyOffset := phase0.PublicKeyLength * len(oldOperators)
	pubKeysSigOffset := pubKeyOffset + phase0.SignatureLength
	sharesExpectedLength := EncryptedKeyLength*len(oldOperators) + pubKeysSigOffset
	if len(keyShares) != sharesExpectedLength {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	position := -1
	for i, op := range oldOperators {
		if operatorID == op.ID {
			position = i
			break
		}
	}
	// check
	if position == -1 {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: operator not found among old operators: %d", operatorID)
	}
	encryptedKeys := utils.SplitBytes(keyShares[pubKeysSigOffset:], len(keyShares[pubKeysSigOffset:])/len(oldOperators))
	// try to decrypt private share
	prShare, err := rsaencryption.DecodeKey(opPrivateKey, encryptedKeys[position])
	if err != nil {
		return nil, 0, err
	}
	secret := &bls.SecretKey{}
	err = secret.SetHexString(string(prShare))
	if err != nil {
		return nil, 0, err
	}
	// find share pub key
	pubKeys := utils.SplitBytes(keyShares[phase0.SignatureLength:pubKeysSigOffset], phase0.PublicKeyLength)
	if len(pubKeys) != len(oldOperators) {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: amount of public keys at keyshares slice is wrong: %d", len(pubKeys))
	}
	publicKey := &bls.PublicKey{}
	err = publicKey.Deserialize(pubKeys[position])
	if err != nil {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: cant deserialize public key at keyshares slice: %d", len(pubKeys))
	}
	if !bytes.Equal(publicKey.Serialize(), secret.GetPublicKey().Serialize()) {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: public key at position %d not equal to operator`s share public key", position)
	}
	return secret, position, nil
}
