package spec

import (
	"bytes"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// ValidateResults returns nil if results array is valid
func ValidateResults(
	operators []*wire.Operator,
	withdrawalCredentials []byte,
	validatorPK []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	requestID [24]byte,
	results []*wire.Result,
) (*bls.PublicKey, *phase0.DepositData, *bls.Sign, error) {
	if len(results) != len(operators) {
		return nil, nil, nil, fmt.Errorf("mistmatch results count")
	}
	// recover and validate validator pk
	pk, err := RecoverValidatorPKFromResults(results)
	if err != nil {
		return nil, nil, nil, err
	}
	if !bytes.Equal(validatorPK, pk) {
		return nil, nil, nil, fmt.Errorf("invalid recovered validator pubkey")
	}

	ids := make([]uint64, 0, len(results))
	sharePubKeys := make([]*bls.PublicKey, 0, len(results))
	sigsPartialDeposit := make([]*bls.Sign, 0, len(results))
	sigsPartialOwnerNonce := make([]*bls.Sign, 0, len(results))
	for _, result := range results {
		if err := ValidateResult(operators, ownerAddress, requestID, withdrawalCredentials, validatorPK, fork, nonce, result); err != nil {
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
	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(ids, sharePubKeys)
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
		Amount:                crypto.MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: crypto.ETH1WithdrawalCredentials(withdrawalCredentials),
		Signature:             phase0.BLSSignature(masterDepositSig.Serialize()),
	}
	err = crypto.VerifyDepositData(network, depositData)
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
	validatorPK []byte,
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
		return fmt.Errorf("failed to verify partial signatures: %v", err)
	}

	// verify ceremony proof
	if err := ValidateCeremonyProof(
		ownerAddress,
		validatorPK,
		operator,
		result.SignedProof,
	); err != nil {
		return fmt.Errorf("failed to validate ceremony proof: %v", err)
	}

	return nil
}

// RecoverValidatorPKFromResults returns validator PK recovered from results
func RecoverValidatorPKFromResults(results []*wire.Result) ([]byte, error) {
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
	err := crypto.VerifyPartialSigs(sigs, pks, hash)
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
		Amount:                crypto.MaxEffectiveBalanceInGwei,
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
func GetOperator(operators []*wire.Operator, id uint64) *wire.Operator {
	for _, operator := range operators {
		if operator.ID == id {
			return operator
		}
	}
	return nil
}

func OperatorIDByPubKey(operators []*wire.Operator, pkBytes []byte) (uint64, error) {
	for _, op := range operators {
		if bytes.Equal(op.PubKey, pkBytes) {
			return op.ID, nil
		}
	}
	return 0, fmt.Errorf("wrong operator")
}

func BLSPKEncode(pkBytes []byte) (*bls.PublicKey, error) {
	ret := &bls.PublicKey{}
	if err := ret.Deserialize(pkBytes); err != nil {
		return nil, err
	}

	return ret, nil
}

func BLSSignatureEncode(pkBytes []byte) (*bls.Sign, error) {
	ret := &bls.Sign{}
	if err := ret.Deserialize(pkBytes); err != nil {
		return nil, err
	}
	return ret, nil
}

func GetPartialSigsFromResult(result *wire.Result) (sharePubKey *bls.PublicKey, depositShareSig, ownerNonceShareSig *bls.Sign, err error) {
	sharePubKey = &bls.PublicKey{}
	if err := sharePubKey.Deserialize(result.SignedProof.Proof.SharePubKey); err != nil {
		return nil, nil, nil, err
	}
	depositShareSig = &bls.Sign{}
	if err := depositShareSig.Deserialize(result.DepositPartialSignature); err != nil {
		return nil, nil, nil, err
	}
	ownerNonceShareSig = &bls.Sign{}
	if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
		return nil, nil, nil, err
	}
	return sharePubKey, depositShareSig, ownerNonceShareSig, nil
}

func ReconstructMasterSignatures(ids []uint64, sigsPartialDeposit, sigsPartialSSVContractOwnerNonce []*bls.Sign) (reconstructedDepositMasterSig, reconstructedOwnerNonceMasterSig *bls.Sign, err error) {
	reconstructedDepositMasterSig, err = crypto.RecoverBLSSignature(ids, sigsPartialDeposit)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	reconstructedOwnerNonceMasterSig, err = crypto.RecoverBLSSignature(ids, sigsPartialSSVContractOwnerNonce)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	return reconstructedDepositMasterSig, reconstructedOwnerNonceMasterSig, nil
}
