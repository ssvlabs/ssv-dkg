package crypto

import (
	"bytes"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// ValidateResults returns nil if results array is valid
func ValidateResults(
	operators []*wire.Operator,
	withdrawalCredentials []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	requestID [24]byte,
	results []*wire.Result,
) (*bls.PublicKey, *phase0.DepositData, *bls.Sign, error) {
	if len(results) != len(operators) {
		return nil, nil, nil, fmt.Errorf("mistmatch results count")
	}
	if err := VerifyValidatorPubKey(results); err != nil {
		return nil, nil, nil, err
	}
	ids := make([]uint64, 0)
	sharePubKeys := make([]*bls.PublicKey, 0)
	sigsPartialDeposit := make([]*bls.Sign, 0)
	sigsPartialOwnerNonce := make([]*bls.Sign, 0)
	for _, result := range results {
		if err := ValidateResult(operators, ownerAddress, requestID, withdrawalCredentials, fork, nonce, result); err != nil {
			return nil, nil, nil, err
		}
		pub, deposit, ownerNonce, err := GetPartialSigsFromResult(result)
		if err != nil {
			return nil, nil, nil, err
		}
		ids = append(ids, result.OperatorID)
		sharePubKeys = append(sharePubKeys, pub)
		sigsPartialDeposit = append(sigsPartialDeposit, deposit)
		sigsPartialOwnerNonce = append(sigsPartialOwnerNonce, ownerNonce)
	}
	validatorRecoveredPK, err := RecoverValidatorPublicKey(ids, sharePubKeys)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to recover validator public key from results")
	}
	masterDepositSig, masterOwnerNonceSig, err := ReconstructMasterSignatures(ids, sigsPartialDeposit, sigsPartialOwnerNonce)
	if err != nil {
		return nil, nil, nil, err
	}
	network, err := utils.GetNetworkByFork(fork)
	if err != nil {
		return nil, nil, nil, err
	}
	depositData := &phase0.DepositData{
		PublicKey:             phase0.BLSPubKey(validatorRecoveredPK.Serialize()),
		Amount:                MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: ETH1WithdrawalCredentials(withdrawalCredentials),
		Signature:             phase0.BLSSignature(masterDepositSig.Serialize()),
	}
	err = VerifyDepositData(network, depositData)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("failed to verify master deposit signature: %v", err)
	}
	data := fmt.Sprintf("%s:%d", common.Address(ownerAddress).String(), nonce)
	hash := eth_crypto.Keccak256([]byte(data))
	if !masterOwnerNonceSig.VerifyByte(validatorRecoveredPK, hash) {
		return nil, nil, nil, fmt.Errorf("failed to verify master owner/nonce signature: %v", err)
	}
	return validatorRecoveredPK, depositData, masterOwnerNonceSig, nil
}

// ValidateResult returns nil if result is valid against init object
func ValidateResult(
	operators []*wire.Operator,
	ownerAddress [20]byte,
	requestID [24]byte,
	withdrawalCredentials []byte,
	fork [4]byte,
	nonce uint64,
	result *wire.Result,
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
		operator,
		result.SignedProof,
	); err != nil {
		return err
	}

	return nil
}

// VerifyValidatorPubKey returns error shares reconstructed validator pub key != individual result validator pub key
func VerifyValidatorPubKey(results []*wire.Result) error {
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

	validatorRecoveredPK, err := RecoverValidatorPublicKey(ids, pks)
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

func VerifyPartialSignatures(
	withdrawalCredentials []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	result *wire.Result,
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
	err := VerifyPartialSigs(sigs, pks, hash[:])
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

	shareRoot, err := ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(validatorPubKey),
		Amount:                MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: ETH1WithdrawalCredentials(withdrawalCredentials)})
	if err != nil {
		return fmt.Errorf("failed to compute deposit data root")
	}

	// Verify partial signatures and recovered threshold signature
	err = VerifyPartialSigs(sigs, pks, shareRoot[:])
	if err != nil {
		return fmt.Errorf("failed to verify deposit partial signatures")
	}
	return nil
}

// GetOperator returns operator by ID or nil if not found
func GetOperator(operators []*wire.Operator, id uint64) *wire.Operator {
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

func GetPartialSigsFromResult(result *wire.Result) (*bls.PublicKey, *bls.Sign, *bls.Sign, error) {
	sharePubKey := &bls.PublicKey{}
	if err := sharePubKey.Deserialize(result.SignedProof.Proof.SharePubKey); err != nil {
		return nil, nil, nil, err
	}
	depositShareSig := &bls.Sign{}
	if err := depositShareSig.Deserialize(result.DepositPartialSignature); err != nil {
		return nil, nil, nil, err
	}
	ownerNonceShareSig := &bls.Sign{}
	if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
		return nil, nil, nil, err
	}
	return sharePubKey, depositShareSig, ownerNonceShareSig, nil
}

func ReconstructMasterSignatures(ids []uint64, sigsPartialDeposit, sigsPartialSSVContractOwnerNonce []*bls.Sign) (*bls.Sign, *bls.Sign, error) {
	reconstructedDepositMasterSig, err := RecoverBLSSignature(ids, sigsPartialDeposit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	reconstructedOwnerNonceMasterSig, err := RecoverBLSSignature(ids, sigsPartialSSVContractOwnerNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	return reconstructedDepositMasterSig, reconstructedOwnerNonceMasterSig, nil
}
