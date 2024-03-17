package testing

import (
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/spec"
	"github.com/bloxapp/ssv-dkg/spec/testing/fixtures"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidateResults(t *testing.T) {
	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results4Operators(),
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResults(
			fixtures.GenerateOperators(7),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results7Operators(),
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResults(
			fixtures.GenerateOperators(10),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results10Operators(),
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResults(
			fixtures.GenerateOperators(13),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			fixtures.Results13Operators(),
		))
	})

	t.Run("invalid share pub key", func(t *testing.T) {
		res := fixtures.Results4Operators()[:3]
		res = append(res, &spec.Result{
			OperatorID:                 4,
			RequestID:                  fixtures.TestRequestID,
			DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator4DepositSignature4Operators),
			OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator4NonceSignature4Operators),
			SignedProof: spec.SignedProof{
				Proof: &spec.Proof{
					ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
					SharePubKey:     fixtures.ShareSK(fixtures.TestValidator7OperatorsShare1).GetPublicKey().Serialize(),
				},
			},
		})
		require.EqualError(t, spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		), "invalid recovered validator pubkey")
	})

	t.Run("too many results", func(t *testing.T) {
		res := fixtures.Results7Operators()
		require.EqualError(t, spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		), "mistmatch results count")
	})

	t.Run("invalid result", func(t *testing.T) {
		res := fixtures.Results4Operators()[:3]
		res = append(res, &spec.Result{
			OperatorID:                 1,
			RequestID:                  fixtures.TestRequestID,
			DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
			OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
			SignedProof:                fixtures.TestOperator1Proof4Operators,
		})
		require.EqualError(t, spec.ValidateResults(
			fixtures.GenerateOperators(4),
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestOwnerAddress,
			fixtures.TestNonce,
			fixtures.TestRequestID,
			res,
		), "failed to recover validator public key from results")
	})
}

func TestValidateResult(t *testing.T) {
	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(7),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
				SignedProof:                fixtures.TestOperator1Proof7Operators,
			},
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(10),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator10Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature10Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature10Operators),
				SignedProof:                fixtures.TestOperator1Proof10Operators,
			},
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateResult(
			fixtures.GenerateOperators(13),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator13Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature13Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature13Operators),
				SignedProof:                fixtures.TestOperator1Proof13Operators,
			},
		))
	})

	t.Run("unknown operator", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 5,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "operator not found")
	})

	t.Run("invalid request ID", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  crypto.NewID(),
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "invalid request ID")
	})

	t.Run("invalid partial deposit signature", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature7Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "failed to verify deposit partial signatures")
	})

	t.Run("invalid partial nonce signature", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature7Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "failed to verify nonce partial signatures")
	})

	t.Run("invalid proof owner address", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof: spec.SignedProof{
					Proof: &spec.Proof{
						ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
						Owner:           [20]byte{},
						SharePubKey:     fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "invalid owner address")
	})

	t.Run("invalid proof signature", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof: spec.SignedProof{
					Proof: &spec.Proof{
						ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
						EncryptedShare:  fixtures.DecodeHexNoError(fixtures.TestValidator4OperatorsShare1),
						Owner:           fixtures.TestOwnerAddress,
						SharePubKey:     fixtures.ShareSK(fixtures.TestValidator4OperatorsShare1).GetPublicKey().Serialize(),
					},
				},
			},
		), "crypto/rsa: verification error")
	})

	t.Run("invalid validator pubkey", func(t *testing.T) {
		require.EqualError(t, spec.ValidateResult(
			fixtures.GenerateOperators(4),
			fixtures.TestOwnerAddress,
			fixtures.TestRequestID,
			fixtures.TestWithdrawalCred,
			fixtures.ShareSK(fixtures.TestValidator7Operators).GetPublicKey().Serialize(),
			fixtures.TestFork,
			fixtures.TestNonce,
			&spec.Result{
				OperatorID:                 1,
				RequestID:                  fixtures.TestRequestID,
				DepositPartialSignature:    fixtures.DecodeHexNoError(fixtures.TestOperator1DepositSignature4Operators),
				OwnerNoncePartialSignature: fixtures.DecodeHexNoError(fixtures.TestOperator1NonceSignature4Operators),
				SignedProof:                fixtures.TestOperator1Proof4Operators,
			},
		), "invalid proof validator pubkey")
	})
}
