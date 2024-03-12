package testing

import (
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/spec"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidateResult(t *testing.T) {
	id := crypto.NewID()

	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
				SignedProof:                TestOperator1Proof4Operators,
			},
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			generateOperators(7),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature7Operators),
				SignedProof:                TestOperator1Proof7Operators,
			},
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			generateOperators(10),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature10Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature10Operators),
				SignedProof:                TestOperator1Proof10Operators,
			},
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			generateOperators(13),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature13Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature13Operators),
				SignedProof:                TestOperator1Proof13Operators,
			},
		))
	})

	t.Run("unknown operator", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 5,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
				SignedProof:                TestOperator1Proof4Operators,
			},
		), "operator not found")
	})

	t.Run("invalid request ID", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  crypto.NewID(),
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
				SignedProof:                TestOperator1Proof4Operators,
			},
		), "invalid request ID")
	})

	t.Run("invalid partial deposit signature", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
				SignedProof:                TestOperator1Proof4Operators,
			},
		), "failed to verify deposit partial signatures")
	})

	t.Run("invalid partial nonce signature", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature7Operators),
				SignedProof:                TestOperator1Proof4Operators,
			},
		), "failed to verify nonce partial signatures")
	})

	t.Run("invalid proof owner address", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
				SignedProof: spec.SignedProof{
					Proof: &spec.Proof{
						ValidatorPubKey: shareSK(TestValidator4Operators).GetPublicKey().Serialize(),
						Owner:           [20]byte{},
						SharePubKey:     shareSK(TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "invalid owner address")
	})

	t.Run("invalid proof signature", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			generateOperators(4),
			TestOwnerAddress,
			id,
			TestWithdrawalCred,
			TestFork,
			TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  id,
				DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
				SignedProof: spec.SignedProof{
					Proof: &spec.Proof{
						ValidatorPubKey: shareSK(TestValidator4Operators).GetPublicKey().Serialize(),
						EncryptedShare:  DecodeHexNoError(TestValidator4OperatorsShare1),
						Owner:           TestOwnerAddress,
						SharePubKey:     shareSK(TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "crypto/rsa: verification error")
	})
}
