package testing

import (
	"github.com/bloxapp/ssv-dkg/spec"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidateInitMessage(t *testing.T) {
	t.Run("valid", func(t *testing.T) {
		require.NoError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             generateOperators(4),
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}))
	})

	t.Run("disordered operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				generateOperators(4)[0],
				generateOperators(4)[1],
				generateOperators(4)[3],
				generateOperators(4)[2],
			},
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "operators and not unique and ordered")
	})
	t.Run("non unique operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				generateOperators(4)[0],
				generateOperators(4)[1],
				generateOperators(4)[2],
				generateOperators(4)[2],
			},
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "operators and not unique and ordered")
	})
	t.Run("no operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             []*spec.Operator{},
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("nil operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             nil,
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("non 3f+1 operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				generateOperators(4)[0],
				generateOperators(4)[1],
				generateOperators(4)[2],
			},
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("non 3f+1 operators", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators: []*spec.Operator{
				generateOperators(7)[0],
				generateOperators(7)[1],
				generateOperators(7)[2],
				generateOperators(7)[3],
				generateOperators(7)[4],
			},
			T:                     3,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
	t.Run("non 2f+1 threshold", func(t *testing.T) {
		require.EqualError(t, spec.ValidateInitMessage(&spec.Init{
			Operators:             generateOperators(4),
			T:                     2,
			WithdrawalCredentials: TestWithdrawalCred,
			Fork:                  TestFork,
			Owner:                 TestOwnerAddress,
			Nonce:                 0,
		}), "threshold set is invalid")
	})
}
