package crypto

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/drand/kyber"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"

	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

func ValidateKeysharesCLI(ks *wire.KeySharesCLI, operators []*spec.Operator, owner [20]byte, nonce uint64, valPub string) error {
	if ks.CreatedAt.String() == "" {
		return fmt.Errorf("keyshares creation time is empty")
	}
	// make sure operators are sorted by ID
	sorted := sort.SliceIsSorted(ks.Shares[0].Payload.OperatorIDs, func(p, q int) bool {
		return ks.Shares[0].Payload.OperatorIDs[p] < ks.Shares[0].Payload.OperatorIDs[q]
	})
	if !sorted {
		return fmt.Errorf("slice is not sorted")
	}
	// 1. check operators at json
	for i, op := range ks.Shares[0].ShareData.Operators {
		if op.ID != operators[i].ID || !bytes.Equal(op.PubKey, operators[i].PubKey) {
			return fmt.Errorf("incorrect keyshares operators")
		}
	}
	// 2. check owner address is correct
	if common.HexToAddress(ks.Shares[0].ShareData.OwnerAddress) != owner {
		return fmt.Errorf("incorrect keyshares owner")
	}
	// 3. check nonce is correct
	if ks.Shares[0].ShareData.OwnerNonce != nonce {
		return fmt.Errorf("incorrect keyshares nonce")
	}
	// 4. check validator public key
	validatorPublicKey, err := hex.DecodeString(strings.TrimPrefix(ks.Shares[0].ShareData.PublicKey, "0x"))
	if err != nil {
		return fmt.Errorf("cant decode validator pub key %w", err)
	}
	if "0x"+valPub != ks.Shares[0].ShareData.PublicKey {
		return fmt.Errorf("incorrect keyshares validator pub key")
	}
	// 5. check operator IDs
	for i, op := range operators {
		if ks.Shares[0].Payload.OperatorIDs[i] != op.ID {
			return fmt.Errorf("incorrect keyshares operator IDs")
		}
	}
	// 6. check validator public key at payload
	if "0x"+valPub != ks.Shares[0].Payload.PublicKey {
		return fmt.Errorf("incorrect keyshares payload validator pub key")
	}
	// 7. check encrypted shares data
	sharesData, err := hex.DecodeString(strings.TrimPrefix(ks.Shares[0].Payload.SharesData, "0x"))
	if err != nil {
		return fmt.Errorf("cant decode enc shares %w", err)
	}
	operatorCount := len(operators)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("shares data len is not correct")
	}
	signature := sharesData[:signatureOffset]
	err = VerifyOwnerNonceSignature(signature, owner, validatorPublicKey, uint16(ks.Shares[0].ShareData.OwnerNonce))
	if err != nil {
		return fmt.Errorf("owner+nonce signature is invalid at keyshares json %w", err)
	}
	// 8. reconstruct validator pub key from shares pub keys
	if err := VerifyValidatorAtSharesData(ks.Shares[0].Payload.OperatorIDs, sharesData, validatorPublicKey); err != nil {
		return err
	}
	return nil
}

func VerifyValidatorAtSharesData(ids []uint64, keyShares, expValPubKey []byte) error {
	// Verify that IDs are unique and ordered.
	if !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] < ids[j] }) {
		return fmt.Errorf("operators not ordered")
	}
	for i := 0; i < len(ids)-1; i++ {
		if ids[i] == ids[i+1] {
			return fmt.Errorf("operators not unique")
		}
	}

	pubKeyOffset := phase0.PublicKeyLength * len(ids)
	pubKeysSigOffset := pubKeyOffset + phase0.SignatureLength
	sharesExpectedLength := EncryptedKeyLength*len(ids) + pubKeysSigOffset
	if len(keyShares) != sharesExpectedLength {
		return fmt.Errorf("GetSecretShareFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	pubKeys := utils.SplitBytes(keyShares[phase0.SignatureLength:pubKeysSigOffset], phase0.PublicKeyLength)
	if len(pubKeys) != len(ids) {
		return fmt.Errorf("GetSecretShareFromSharesData: amount of public keys at keyshares slice is wrong: %d", len(pubKeys))
	}
	var sharePublicKeys []*bls.PublicKey
	for i := 0; i < len(ids); i++ {
		// find share pub key

		publicKey := &bls.PublicKey{}
		err := publicKey.Deserialize(pubKeys[i])
		if err != nil {
			return fmt.Errorf("GetSecretShareFromSharesData: cant deserialize public key at keyshares slice: %d", len(pubKeys))
		}
		sharePublicKeys = append(sharePublicKeys, publicKey)
	}
	validatorRecoveredPK, err := spec_crypto.RecoverValidatorPublicKey(ids, sharePublicKeys)
	if err != nil {
		return fmt.Errorf("failed to recover validator public key from shares data: %w", err)
	}
	validatorRecoveredPKBytes := validatorRecoveredPK.Serialize()
	if !bytes.Equal(expValPubKey, validatorRecoveredPKBytes) {
		return fmt.Errorf("validator public key recovered from shares is different: exp %x, got %x", expValPubKey, validatorRecoveredPKBytes)
	}
	return nil
}

func GetPubCommitsFromSharesData(operators []*spec.Operator, keyshares []byte, threshold int) ([]kyber.Point, error) {
	suite := kyber_bls12381.NewBLS12381Suite()
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*len(operators) + signatureOffset
	sharesExpectedLength := EncryptedKeyLength*len(operators) + pubKeysOffset
	if len(keyshares) != sharesExpectedLength {
		return nil, fmt.Errorf("GetPubCommitsFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyshares))
	}
	pubKeys := utils.SplitBytes(keyshares[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	// try to recover commits
	var kyberPubShares []*share.PubShare
	for i, pubk := range pubKeys {
		blsPub := &bls.PublicKey{}
		err := blsPub.Deserialize(pubk)
		if err != nil {
			return nil, err
		}
		v := suite.G1().Point()
		err = v.UnmarshalBinary(blsPub.Serialize())
		if err != nil {
			return nil, err
		}
		kyberPubhare := &share.PubShare{
			I: int(i),
			V: v,
		}
		kyberPubShares = append(kyberPubShares, kyberPubhare)
	}
	pubPoly, err := share.RecoverPubPoly(suite.G1(), kyberPubShares, threshold, len(operators))
	if err != nil {
		return nil, err
	}
	_, commits := pubPoly.Info()
	return commits, nil
}

func GetSecretShareFromSharesData(keyshares, initiatorPublicKey, ceremonySigs []byte, oldOperators []*wire.Operator, opPrivateKey *rsa.PrivateKey, operatorID uint64) (*share.PriShare, error) {
	suite := kyber_bls12381.NewBLS12381Suite()
	secret, position, err := checkKeySharesSlice(keyshares, oldOperators, operatorID, opPrivateKey)
	if err != nil {
		return nil, err
	}
	var kyberPrivShare *share.PriShare
	// Check operator signature
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPublicKey)
	if err != nil {
		return nil, err
	}
	encInitPub, err := spec_crypto.EncodeRSAPublicKey(initiatorPubKey)
	if err != nil {
		return nil, err
	}
	sigs := utils.SplitBytes(ceremonySigs, SignatureLength)
	serialized := secret.Serialize()
	dataToVerify := make([]byte, len(serialized)+len(encInitPub))
	copy(dataToVerify[:len(serialized)], serialized)
	copy(dataToVerify[len(serialized):], encInitPub)
	err = spec_crypto.VerifyRSA(&opPrivateKey.PublicKey, dataToVerify, sigs[position])
	if err != nil {
		return nil, fmt.Errorf("cant verify initiator public key")
	}
	v := suite.G1().Scalar().SetBytes(serialized)
	kyberPrivShare = &share.PriShare{
		I: int(operatorID),
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
