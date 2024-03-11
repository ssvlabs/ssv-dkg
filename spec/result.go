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
func ValidateResults(init *Init, requestID [24]byte, results []*Result) error {
	if len(results) != len(init.Operators) {
		return fmt.Errorf("mistmatch results count")
	}

	for _, result := range results {
		if err := ValidateResult(init, requestID, result); err != nil {
			return err
		}
	}

	if err := VerifyValidatorPubKey(results); err != nil {
		return err
	}

	if err := VerifyPartialSignatures(init, results[0].SignedProof.Proof.ValidatorPubKey, results); err != nil {
		return err
	}

	return nil
}

// ValidateResult returns nil if result is valid against init object
func ValidateResult(init *Init, requestID [24]byte, result *Result) error {
	// verify operator
	operator := GetOperator(init.Operators, result.OperatorID)
	if operator == nil {
		return fmt.Errorf("operator not found")
	}

	// verify request ID
	if !bytes.Equal(requestID[:], result.RequestID[:]) {
		return fmt.Errorf("invalid request ID")
	}

	// verify ceremony proof
	if err := VerifyCeremonyProof(operator.PubKey, result.SignedProof); err != nil {
		return err
	}

	return nil
}

func VerifyValidatorPubKey(results []*Result) error {
	ids := make([]uint64, len(results))
	pks := make([]*bls.PublicKey, len(results))

	for i, result := range results {
		pk, err := BLSPKEncode(result.SignedProof.Proof.SharePubKey)
		if err != nil {
			return err
		}
		pks[i] = pk
		ids[i] = result.OperatorID
	}

	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(ids, pks)
	if err != nil {
		return fmt.Errorf("failed to recover validator public key from results")
	}

	for _, result := range results {
		if !bytes.Equal(validatorRecoveredPK.Serialize(), result.SignedProof.Proof.ValidatorPubKey) {
			return fmt.Errorf("mistmatch result validator PK")
		}
	}
	return nil
}

func VerifyPartialSignatures(init *Init, validatorPubKey []byte, results []*Result) error {
	pks := make([]*bls.PublicKey, len(results))
	depositSigs := make([]*bls.Sign, len(results))
	nonceSigs := make([]*bls.Sign, len(results))

	for i, result := range results {
		pk, err := BLSPKEncode(result.SignedProof.Proof.SharePubKey)
		if err != nil {
			return err
		}
		pks[i] = pk

		depositSig, err := BLSSignatureEncode(result.DepositPartialSignature)
		if err != nil {
			return err
		}
		depositSigs[i] = depositSig

		nonceSig, err := BLSSignatureEncode(result.OwnerNoncePartialSignature)
		if err != nil {
			return err
		}
		nonceSigs[i] = nonceSig
	}

	if err := VerifyPartialDepositDataSignatures(init, validatorPubKey, depositSigs, pks); err != nil {
		return err
	}

	if err := VerifyPartialNonceSignatures(init, nonceSigs, pks); err != nil {
		return err
	}

	return nil
}

func VerifyPartialNonceSignatures(init *Init, sigs []*bls.Sign, pks []*bls.PublicKey) error {
	data := fmt.Sprintf("%s:%d", common.Address(init.Owner).String(), init.Nonce)
	hash := eth_crypto.Keccak256([]byte(data))

	// Verify partial signatures and recovered threshold signature
	err := crypto.VerifyPartialSigs(sigs, pks, hash[:])
	if err != nil {
		return fmt.Errorf("failed to verify nonce partial signatures")
	}
	return nil
}

func VerifyPartialDepositDataSignatures(init *Init, validatorPubKey []byte, sigs []*bls.Sign, pks []*bls.PublicKey) error {
	network, err := utils.GetNetworkByFork(init.Fork)
	if err != nil {
		return err
	}

	shareRoot, err := crypto.ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(validatorPubKey),
		Amount:                dkg.MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: crypto.ETH1WithdrawalCredentials(init.WithdrawalCredentials)})
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
