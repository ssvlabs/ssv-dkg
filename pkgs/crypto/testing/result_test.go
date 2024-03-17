package testing

import (
	"testing"

	"github.com/stretchr/testify/require"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto/testing/fixtures"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func TestValidateResults(t *testing.T) {
	t.Run("valid 4 operators", func(t *testing.T) {
		_, _, _, err := crypto.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results4Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		_, _, _, err := crypto.ValidateResults(
			fixtures.GenerateOperators(7),
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results7Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		_, _, _, err := crypto.ValidateResults(
			fixtures.GenerateOperators(10),
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results10Operators(),
		)
		require.NoError(t, err)
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		_, _, _, err := crypto.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators(),
		)
		require.NoError(t, err)
	})
}

func TestValidateResult(t *testing.T) {
	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(7),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
				SignedProof:                fixtures.TestOperator1Proof7Operators,
			},
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(10),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature10Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature10Operators),
				SignedProof:                fixtures.TestOperator1Proof10Operators,
			},
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(13),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature13Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature13Operators),
				SignedProof:                fixtures.TestOperator1Proof13Operators,
			},
		))
	})

	t.Run("unknown operator", func(t *testing.T) {
		require.EqualError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 5,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "operator not found")
	})

	t.Run("invalid request ID", func(t *testing.T) {
		require.EqualError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  crypto.NewID(),
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "invalid request ID")
	})

	t.Run("invalid partial deposit signature", func(t *testing.T) {
		require.EqualError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "failed to verify partial signatures: failed to verify deposit partial signatures")
	})

	t.Run("invalid partial nonce signature", func(t *testing.T) {
		require.EqualError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "failed to verify partial signatures: failed to verify nonce partial signatures")
	})

	t.Run("invalid proof owner address", func(t *testing.T) {
		require.EqualError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof: wire.SignedProof{
					Proof: &wire.Proof{
						ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
						Owner:           [20]byte{},
						SharePubKey:     fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "failed to validate ceremony proof: invalid owner address")
	})

	t.Run("invalid proof signature", func(t *testing.T) {
		require.EqualError(t, crypto.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.TestFork,
			fixtures.TestNonce,
			&wire.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof: wire.SignedProof{
					Proof: &wire.Proof{
						ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
						EncryptedShare:  fixtures.DecodeHexNoError(fixtures.TestValidator4OperatorsShare1),
						Owner:           fixtures.TestOwnerAddress,
						SharePubKey:     fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "crypto/rsa: verification error")
	})
}
