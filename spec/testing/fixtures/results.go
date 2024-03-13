package fixtures

import "github.com/bloxapp/ssv-dkg/spec"

func Results4Operators() []*spec.Result {
	return []*spec.Result{
		{
			OperatorID:                 1,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature4Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature4Operators),
			SignedProof:                TestOperator1Proof4Operators,
		},
		{
			OperatorID:                 2,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator2DepositSignature4Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator2NonceSignature4Operators),
			SignedProof:                TestOperator2Proof4Operators,
		},
		{
			OperatorID:                 3,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator3DepositSignature4Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator3NonceSignature4Operators),
			SignedProof:                TestOperator3Proof4Operators,
		},
		{
			OperatorID:                 4,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator4DepositSignature4Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator4NonceSignature4Operators),
			SignedProof:                TestOperator4Proof4Operators,
		},
	}
}

func Results7Operators() []*spec.Result {
	return []*spec.Result{
		{
			OperatorID:                 1,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature7Operators),
			SignedProof:                TestOperator1Proof7Operators,
		},
		{
			OperatorID:                 2,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator2DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator2NonceSignature7Operators),
			SignedProof:                TestOperator2Proof7Operators,
		},
		{
			OperatorID:                 3,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator3DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator3NonceSignature7Operators),
			SignedProof:                TestOperator3Proof7Operators,
		},
		{
			OperatorID:                 4,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator4DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator4NonceSignature7Operators),
			SignedProof:                TestOperator4Proof7Operators,
		},
		{
			OperatorID:                 5,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator5DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator5NonceSignature7Operators),
			SignedProof:                TestOperator5Proof7Operators,
		},
		{
			OperatorID:                 6,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator6DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator6NonceSignature7Operators),
			SignedProof:                TestOperator6Proof7Operators,
		},
		{
			OperatorID:                 7,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator7DepositSignature7Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator7NonceSignature7Operators),
			SignedProof:                TestOperator7Proof7Operators,
		},
	}
}
