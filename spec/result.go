package spec

import (
	"bytes"
	"fmt"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
)

// ValidateResults returns nil if results array is valid
func ValidateResults(
	operators []*Operator,
	withdrawalCredentials []byte,
	validatorPK []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	requestID [24]byte,
	results []*Result,
) error {
	if len(results) != len(operators) {
		return fmt.Errorf("mistmatch results count")
	}

	// recover and validate validator pk
	pk, err := RecoverValidatorPKFromResults(results)
	if err != nil {
		return err
	}
	if !bytes.Equal(validatorPK, pk) {
		return fmt.Errorf("invalid recovered validator pubkey")
	}

	for _, result := range results {
		if err := ValidateResult(
			operators,
			ownerAddress,
			requestID,
			withdrawalCredentials,
			validatorPK,
			fork,
			nonce,
			result,
		); err != nil {
			return err
		}
	}

	return nil
}

// ValidateResult returns nil if result is valid against init object
func ValidateResult(
	operators []*Operator,
	ownerAddress [20]byte,
	requestID [24]byte,
	withdrawalCredentials []byte,
	validatorPK []byte,
	fork [4]byte,
	nonce uint64,
	result *Result,
) error {
	// verify operator
	operator := GetOperator(operators, result.OperatorID)
	if operator == nil {
		return fmt.Errorf("operator not found")
	}

	// verify request ID
	if !bytes.Equal(requestID[:], result.RequestID[:]) {
		return fmt.Errorf("invalid request ID")
	}

	if err := VerifyPartialSignatures(
		withdrawalCredentials,
		fork,
		ownerAddress,
		nonce,
		result,
	); err != nil {
		return err
	}

	// verify ceremony proof
	if err := ValidateCeremonyProof(
		ownerAddress,
		validatorPK,
		operator,
		result.SignedProof,
	); err != nil {
		return err
	}

	return nil
}

// RecoverValidatorPKFromResults returns validator PK recovered from results
func RecoverValidatorPKFromResults(results []*Result) ([]byte, error) {
	ids := make([]uint64, len(results))
	pks := make([]*bls.PublicKey, len(results))

	for i, result := range results {
		pk, err := BLSPKEncode(result.SignedProof.Proof.SharePubKey)
		if err != nil {
			return nil, err
		}
		pks[i] = pk
		ids[i] = result.OperatorID
	}

	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(ids, pks)
	if err != nil {
		return nil, fmt.Errorf("failed to recover validator public key from results")
	}

	return validatorRecoveredPK.Serialize(), nil
}

func VerifyPartialSignatures(
	withdrawalCredentials []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	result *Result,
) error {
	pk, err := BLSPKEncode(result.SignedProof.Proof.SharePubKey)
	if err != nil {
		return err
	}

	depositSig, err := BLSSignatureEncode(result.DepositPartialSignature)
	if err != nil {
		return err
	}

	nonceSig, err := BLSSignatureEncode(result.OwnerNoncePartialSignature)
	if err != nil {
		return err
	}

	if err := VerifyPartialDepositDataSignatures(
		withdrawalCredentials,
		fork,
		result.SignedProof.Proof.ValidatorPubKey,
		[]*bls.Sign{depositSig},
		[]*bls.PublicKey{pk},
	); err != nil {
		return err
	}

	if err := VerifyPartialNonceSignatures(ownerAddress, nonce, []*bls.Sign{nonceSig}, []*bls.PublicKey{pk}); err != nil {
		return err
	}

	return nil
}

func VerifyPartialNonceSignatures(
	ownerAddress [20]byte,
	nonce uint64,
	sigs []*bls.Sign,
	pks []*bls.PublicKey,
) error {
	data := fmt.Sprintf("%s:%d", common.Address(ownerAddress).String(), nonce)
	hash := eth_crypto.Keccak256([]byte(data))

	// Verify partial signatures and recovered threshold signature
	err := crypto.VerifyPartialSigs(sigs, pks, hash[:])
	if err != nil {
		return fmt.Errorf("failed to verify nonce partial signatures")
	}
	return nil
}

func VerifyPartialDepositDataSignatures(
	withdrawalCredentials []byte,
	fork [4]byte,
	validatorPubKey []byte,
	sigs []*bls.Sign,
	pks []*bls.PublicKey,
) error {
	network, err := utils.GetNetworkByFork(fork)
	if err != nil {
		return err
	}

	shareRoot, err := crypto.ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(validatorPubKey),
		Amount:                dkg.MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: crypto.ETH1WithdrawalCredentials(withdrawalCredentials)})
	if err != nil {
		return fmt.Errorf("failed to compute deposit data root")
	}

	// Verify partial signatures and recovered threshold signature
	err = crypto.VerifyPartialSigs(sigs, pks, shareRoot[:])
	if err != nil {
		return fmt.Errorf("failed to verify deposit partial signatures")
	}
	return nil
}

// GetOperator returns operator by ID or nil if not found
func GetOperator(operators []*Operator, id uint64) *Operator {
	for _, operator := range operators {
		if operator.ID == id {
			return operator
		}
	}
	return nil
}

func BLSPKEncode(pkBytes []byte) (*bls.PublicKey, error) {
	ret := &bls.PublicKey{}
	return ret, ret.Deserialize(pkBytes)
}

func BLSSignatureEncode(pkBytes []byte) (*bls.Sign, error) {
	ret := &bls.Sign{}
	return ret, ret.Deserialize(pkBytes)
}
