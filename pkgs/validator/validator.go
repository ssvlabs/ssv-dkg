package validator

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func ValidateResults(depositDataArr []*wire.DepositDataCLI, keySharesArr []*wire.KeySharesCLI, proofs [][]*wire.SignedProof, validators int) error {
	// check len or files
	if len(depositDataArr) != len(keySharesArr) || len(depositDataArr) != len(proofs) || len(depositDataArr) != validators {
		return fmt.Errorf("incorrect len of results")
	}
	if err := checkValidatorsCorrectAtDeposits(depositDataArr); err != nil {
		return err
	}
	if err := checkNonceOrderCorrect(keySharesArr); err != nil {
		return err
	}
	// validate crypto and make sure validator correct everywhere
	for i := 0; i < validators; i++ {
		// make sure fields are same across files
		if depositDataArr[i].PubKey != strings.TrimPrefix(keySharesArr[i].Shares[0].Payload.PublicKey, "0x") {
			return fmt.Errorf("validator doesnt match: exp %s, got %s", depositDataArr[i].PubKey, strings.TrimPrefix(keySharesArr[i].Shares[0].Payload.PublicKey, "0x"))
		}
		err := crypto.ValidateDepositDataCLI(depositDataArr[i])
		if err != nil {
			return fmt.Errorf("err validating deposit data %w", err)
		}
		err = ValidateKeyshare(keySharesArr[i], depositDataArr[i].PubKey)
		if err != nil {
			return fmt.Errorf("err validating keyshares data %w", err)
		}
		err = validateSignedProofs(keySharesArr[i], proofs)
		if err != nil {
			return fmt.Errorf("err validating proofs %w", err)
		}
	}
	return nil
}

func checkNonceOrderCorrect(keySharesArr []*wire.KeySharesCLI) error {
	// check the nonce order
	startNonce := keySharesArr[0].Shares[0].OwnerNonce
	for i := 1; i < len(keySharesArr); i++ {
		startNonce++
		if keySharesArr[i].Shares[0].OwnerNonce != startNonce {
			return fmt.Errorf("incorrect order of nonces at keyshares JSON")
		}
	}
	return nil
}

func checkValidatorsCorrectAtDeposits(depositDataArr []*wire.DepositDataCLI) error {
	validator := depositDataArr[0].PubKey
	for _, dep := range depositDataArr {
		if validator != dep.PubKey {
			return fmt.Errorf("validators not same at deposit data files")
		}
	}
	return nil
}

func validateSignedProofs(keyshare *wire.KeySharesCLI, proofs [][]*wire.SignedProof) error {
	for _, proof := range proofs {
		for i := 0; i < len(keyshare.Shares[0].Operators); i++ {
			// compare fields
			valShares, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].PublicKey, "0x"))
			if err != nil {
				return err
			}
			if !bytes.Equal(valShares, proof[i].Proof.ValidatorPubKey) {
				return fmt.Errorf("validator doesnt match: exp %x, got %x", proof[i].Proof.ValidatorPubKey, valShares)
			}
			owner, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].ShareData.OwnerAddress, "0x"))
			if err != nil {
				return err
			}
			if !bytes.Equal(owner, proof[i].Proof.Owner[:]) {
				return fmt.Errorf("validator public key at proof doesnt match validator public key at keyshares")
			}

			sharesData, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].Payload.SharesData, "0x"))
			if err != nil {
				return fmt.Errorf("cant decode enc shares %w", err)
			}
			encShare, err := getEncryptedShareFromSharesdata(sharesData, keyshare.Shares[0].Operators, keyshare.Shares[0].Operators[i].ID)
			if err != nil {
				return fmt.Errorf("cant get enc shares from shares data %w", err)
			}
			if !bytes.Equal(encShare, proof[i].Proof.EncryptedShare) {
				return fmt.Errorf("encrypted share doesnt match it at proof")
			}
			sharePub, err := getSharePubKeyFromSharesdata(sharesData, keyshare.Shares[0].Operators, keyshare.Shares[0].Operators[i].ID)
			if err != nil {
				return fmt.Errorf("cant get share pub key from shares data %w", err)
			}
			if !bytes.Equal(sharePub, proof[i].Proof.SharePubKey) {
				return fmt.Errorf("encrypted share doesnt match it at proof")
			}
			// validate proof
			if err := crypto.ValidateCeremonyProof(common.HexToAddress(keyshare.Shares[0].OwnerAddress), keyshare.Shares[0].Operators[i], proof[i]); err != nil {
				return err
			}
		}
	}
	return nil
}

func ValidateKeyshare(keyshare *wire.KeySharesCLI, valPub string) error {
	if keyshare.CreatedAt.String() == "" {
		return fmt.Errorf("keyshares creation time is empty")
	}
	// make sure operators are sorted by ID
	sorted := sort.SliceIsSorted(keyshare.Shares[0].Payload.OperatorIDs, func(p, q int) bool {
		return keyshare.Shares[0].Payload.OperatorIDs[p] < keyshare.Shares[0].Payload.OperatorIDs[q]
	})
	if !sorted {
		return fmt.Errorf("slice is not sorted")
	}
	// check validator public key
	validatorPublicKey, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].PublicKey, "0x"))
	if err != nil {
		return fmt.Errorf("cant decode validator pub key %w", err)
	}
	if "0x"+valPub != keyshare.Shares[0].PublicKey {
		return fmt.Errorf("incorrect keyshares validator pub key")
	}
	// check validator public key at payload
	if "0x"+valPub != keyshare.Shares[0].Payload.PublicKey {
		return fmt.Errorf("incorrect keyshares payload validator pub key")
	}
	// 7. check encrypded shares data
	sharesData, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].Payload.SharesData, "0x"))
	if err != nil {
		return fmt.Errorf("cant decode enc shares %w", err)
	}
	operatorCount := len(keyshare.Shares[0].Operators)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("shares data len is not correct")
	}
	signature := sharesData[:signatureOffset]
	err = crypto.VerifyOwnerNonceSignature(signature, common.HexToAddress(keyshare.Shares[0].OwnerAddress), validatorPublicKey, uint16(keyshare.Shares[0].OwnerNonce))
	if err != nil {
		return fmt.Errorf("owner+nonce signature is invalid at keyshares json %w", err)
	}
	// 8. reconstruct validator pub key from shares pub keys
	if err := crypto.VerifyValidatorAtSharesData(keyshare.Shares[0].Payload.OperatorIDs, sharesData, validatorPublicKey); err != nil {
		return err
	}
	return nil
}

func getEncryptedShareFromSharesdata(keyShares []byte, operators []*wire.Operator, operatorID uint64) ([]byte, error) {
	pubKeyOffset := phase0.PublicKeyLength * len(operators)
	pubKeysSigOffset := pubKeyOffset + phase0.SignatureLength
	sharesExpectedLength := crypto.EncryptedKeyLength*len(operators) + pubKeysSigOffset
	if len(keyShares) != sharesExpectedLength {
		return nil, fmt.Errorf("GetSecretShareFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	position := -1
	for i, op := range operators {
		if operatorID == op.ID {
			position = i
			break
		}
	}
	// check
	if position == -1 {
		return nil, fmt.Errorf("GetSecretShareFromSharesData: operator not found among old operators: %d", operatorID)
	}
	encryptedKeys := utils.SplitBytes(keyShares[pubKeysSigOffset:], len(keyShares[pubKeysSigOffset:])/len(operators))
	return encryptedKeys[position], nil
}

func getSharePubKeyFromSharesdata(keyShares []byte, operators []*wire.Operator, operatorID uint64) ([]byte, error) {
	pubKeyOffset := phase0.PublicKeyLength * len(operators)
	pubKeysSigOffset := pubKeyOffset + phase0.SignatureLength
	sharesExpectedLength := crypto.EncryptedKeyLength*len(operators) + pubKeysSigOffset
	if len(keyShares) != sharesExpectedLength {
		return nil, fmt.Errorf("GetSecretShareFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	position := -1
	for i, op := range operators {
		if operatorID == op.ID {
			position = i
			break
		}
	}
	// check
	if position == -1 {
		return nil, fmt.Errorf("GetSecretShareFromSharesData: operator not found among old operators: %d", operatorID)
	}
	pubKeys := utils.SplitBytes(keyShares[phase0.SignatureLength:pubKeysSigOffset], phase0.PublicKeyLength)
	return pubKeys[position], nil
}
