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

func Results10Operators() []*spec.Result {
	return []*spec.Result{
		{
			OperatorID:                 1,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature10Operators),
			SignedProof:                TestOperator1Proof10Operators,
		},
		{
			OperatorID:                 2,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator2DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator2NonceSignature10Operators),
			SignedProof:                TestOperator2Proof10Operators,
		},
		{
			OperatorID:                 3,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator3DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator3NonceSignature10Operators),
			SignedProof:                TestOperator3Proof10Operators,
		},
		{
			OperatorID:                 4,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator4DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator4NonceSignature10Operators),
			SignedProof:                TestOperator4Proof10Operators,
		},
		{
			OperatorID:                 5,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator5DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator5NonceSignature10Operators),
			SignedProof:                TestOperator5Proof10Operators,
		},
		{
			OperatorID:                 6,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator6DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator6NonceSignature10Operators),
			SignedProof:                TestOperator6Proof10Operators,
		},
		{
			OperatorID:                 7,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator7DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator7NonceSignature10Operators),
			SignedProof:                TestOperator7Proof10Operators,
		},
		{
			OperatorID:                 8,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator8DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator8NonceSignature10Operators),
			SignedProof:                TestOperator8Proof10Operators,
		},
		{
			OperatorID:                 9,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator9DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator9NonceSignature10Operators),
			SignedProof:                TestOperator9Proof10Operators,
		},
		{
			OperatorID:                 10,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator10DepositSignature10Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator10NonceSignature10Operators),
			SignedProof:                TestOperator10Proof10Operators,
		},
	}
}

func Results13Operators() []*spec.Result {
	return []*spec.Result{
		{
			OperatorID:                 1,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator1DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator1NonceSignature13Operators),
			SignedProof:                TestOperator1Proof13Operators,
		},
		{
			OperatorID:                 2,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator2DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator2NonceSignature13Operators),
			SignedProof:                TestOperator2Proof13Operators,
		},
		{
			OperatorID:                 3,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator3DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator3NonceSignature13Operators),
			SignedProof:                TestOperator3Proof13Operators,
		},
		{
			OperatorID:                 4,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator4DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator4NonceSignature13Operators),
			SignedProof:                TestOperator4Proof13Operators,
		},
		{
			OperatorID:                 5,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator5DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator5NonceSignature13Operators),
			SignedProof:                TestOperator5Proof13Operators,
		},
		{
			OperatorID:                 6,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator6DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator6NonceSignature13Operators),
			SignedProof:                TestOperator6Proof13Operators,
		},
		{
			OperatorID:                 7,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator7DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator7NonceSignature13Operators),
			SignedProof:                TestOperator7Proof13Operators,
		},
		{
			OperatorID:                 8,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator8DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator8NonceSignature13Operators),
			SignedProof:                TestOperator8Proof13Operators,
		},
		{
			OperatorID:                 9,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator9DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator9NonceSignature13Operators),
			SignedProof:                TestOperator9Proof13Operators,
		},
		{
			OperatorID:                 10,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator10DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator10NonceSignature13Operators),
			SignedProof:                TestOperator10Proof13Operators,
		},
		{
			OperatorID:                 11,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator11DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator11NonceSignature13Operators),
			SignedProof:                TestOperator11Proof13Operators,
		},
		{
			OperatorID:                 12,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator12DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator12NonceSignature13Operators),
			SignedProof:                TestOperator12Proof13Operators,
		},
		{
			OperatorID:                 13,
			RequestID:                  TestRequestID,
			DepositPartialSignature:    DecodeHexNoError(TestOperator13DepositSignature13Operators),
			OwnerNoncePartialSignature: DecodeHexNoError(TestOperator13NonceSignature13Operators),
			SignedProof:                TestOperator13Proof13Operators,
		},
	}
}
