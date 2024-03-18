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

func ValidateResults(
	allDepositData []*wire.DepositDataCLI,
	allKeyshares *wire.KeySharesCLI,
	allProofs [][]*wire.SignedProof,
	expectedValidatorCount int,
	expectedOwnerAddress common.Address,
	expectedOwnerNonce uint64,
	expectedWithdrawAddress common.Address,
) error {
	// check len or files
	if len(allDepositData) != len(allKeyshares.Shares) || len(allDepositData) != len(allProofs) || len(allDepositData) != expectedValidatorCount {
		return fmt.Errorf("incorrect len of results")
	}
	if expectedWithdrawAddress == (common.Address{}) {
		return fmt.Errorf("withdraw address is empty")
	}
	if err := checkValidatorsCorrectAtDeposits(allDepositData); err != nil {
		return err
	}
	// validate crypto and make sure validator correct everywhere
	nonce := expectedOwnerNonce
	for i := 0; i < expectedValidatorCount; i++ {
		// make sure fields are same across files
		keyshares := allKeyshares.Shares[i]
		depositData := allDepositData[i]
		proofs := allProofs[i]
		if depositData.PubKey != strings.TrimPrefix(keyshares.Payload.PublicKey, "0x") {
			return fmt.Errorf("validator doesnt match: %s in deposit-data, %s in keyshares", depositData.PubKey, strings.TrimPrefix(keyshares.Payload.PublicKey, "0x"))
		}
		err := crypto.ValidateDepositDataCLI(depositData, expectedWithdrawAddress)
		if err != nil {
			return fmt.Errorf("err validating deposit data %w", err)
		}
		soloKeyshares := &wire.KeySharesCLI{
			CreatedAt: allKeyshares.CreatedAt,
			Version:   allKeyshares.Version,
			Shares:    []wire.Data{keyshares},
		}
		err = ValidateKeyshare(soloKeyshares, depositData.PubKey, expectedOwnerAddress.Hex(), nonce)
		if err != nil {
			return fmt.Errorf("err validating keyshares data %w", err)
		}
		err = validateSignedProofs(soloKeyshares, proofs)
		if err != nil {
			return fmt.Errorf("err validating proofs %w", err)
		}
		nonce++
	}
	return nil
}

func checkValidatorsCorrectAtDeposits(depositDataArr []*wire.DepositDataCLI) error {
	pubkeys := map[string]struct{}{}
	for _, dep := range depositDataArr {
		if _, ok := pubkeys[dep.PubKey]; ok {
			return fmt.Errorf("duplicate validator public key")
		}
		pubkeys[dep.PubKey] = struct{}{}
	}
	return nil
}

func validateSignedProofs(keyshare *wire.KeySharesCLI, proofs []*wire.SignedProof) error {
	for i := 0; i < len(keyshare.Shares[0].Operators); i++ {
		// compare fields
		valShares, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].PublicKey, "0x"))
		if err != nil {
			return err
		}
		if !bytes.Equal(valShares, proofs[i].Proof.ValidatorPubKey) {
			return fmt.Errorf("validator doesnt match: %x in proof, %x in keyshares", proofs[i].Proof.ValidatorPubKey, valShares)
		}
		owner, err := hex.DecodeString(strings.TrimPrefix(keyshare.Shares[0].ShareData.OwnerAddress, "0x"))
		if err != nil {
			return err
		}
		if !bytes.Equal(owner, proofs[i].Proof.Owner[:]) {
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
		if !bytes.Equal(encShare, proofs[i].Proof.EncryptedShare) {
			return fmt.Errorf("encrypted share doesnt match it at proof")
		}
		sharePub, err := getSharePubKeyFromSharesdata(sharesData, keyshare.Shares[0].Operators, keyshare.Shares[0].Operators[i].ID)
		if err != nil {
			return fmt.Errorf("cant get share pub key from shares data %w", err)
		}
		if !bytes.Equal(sharePub, proofs[i].Proof.SharePubKey) {
			return fmt.Errorf("encrypted share doesnt match it at proof")
		}
		// validate proof
		if err := crypto.ValidateCeremonyProof(common.HexToAddress(keyshare.Shares[0].OwnerAddress), keyshare.Shares[0].Operators[i], proofs[i]); err != nil {
			return err
		}
	}
	return nil
}

func ValidateKeyshare(keyshare *wire.KeySharesCLI, expectedValidatorPubkey string, expectedOwnerAddress string, expectedOwnerNonce uint64) error {
	if keyshare.CreatedAt.String() == "" {
		return fmt.Errorf("keyshares creation time is empty")
	}
	for _, share := range keyshare.Shares {
		if !crypto.UniqueAndOrderedOperators(share.Operators) {
			return fmt.Errorf("operators and not unique and ordered")
		}

		if share.OwnerAddress != expectedOwnerAddress {
			return fmt.Errorf("incorrect keyshares owner address")
		}
		if share.OwnerNonce != expectedOwnerNonce {
			return fmt.Errorf("incorrect keyshares owner nonce")
		}

		// make sure operators are sorted by ID
		sorted := sort.SliceIsSorted(share.Payload.OperatorIDs, func(p, q int) bool {
			return share.Payload.OperatorIDs[p] < share.Payload.OperatorIDs[q]
		})
		if !sorted {
			return fmt.Errorf("slice is not sorted")
		}

		// check validator public key
		validatorPublicKey, err := hex.DecodeString(strings.TrimPrefix(share.PublicKey, "0x"))
		if err != nil {
			return fmt.Errorf("cant decode validator pub key %w", err)
		}
		if "0x"+expectedValidatorPubkey != share.PublicKey {
			return fmt.Errorf("incorrect keyshares validator pub key")
		}
		if "0x"+expectedValidatorPubkey != share.Payload.PublicKey {
			return fmt.Errorf("incorrect keyshares payload validator pub key")
		}

		// 7. check encrypded shares data
		sharesData, err := hex.DecodeString(strings.TrimPrefix(share.Payload.SharesData, "0x"))
		if err != nil {
			return fmt.Errorf("cant decode enc shares %w", err)
		}
		operatorCount := len(share.Operators)
		signatureOffset := phase0.SignatureLength
		pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
		sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
		if len(sharesData) != sharesExpectedLength {
			return fmt.Errorf("shares data len is not correct")
		}
		signature := sharesData[:signatureOffset]
		err = crypto.VerifyOwnerNonceSignature(signature, common.HexToAddress(share.OwnerAddress), validatorPublicKey, uint16(share.OwnerNonce))
		if err != nil {
			return fmt.Errorf("owner+nonce signature is invalid at keyshares json %w", err)
		}

		// 8. reconstruct validator pub key from shares pub keys
		if err := crypto.VerifyValidatorAtSharesData(share.Payload.OperatorIDs, sharesData, validatorPublicKey); err != nil {
			return err
		}
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
