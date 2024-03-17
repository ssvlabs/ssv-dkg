package testing

import (
	"github.com/bloxapp/ssv-dkg/spec"
	"github.com/bloxapp/ssv-dkg/spec/testing/fixtures"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestValidateReshare(t *testing.T) {
	t.Run("valid 4 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateReshareMessage(
			fixtures.TestReshare4Operators,
			map[*spec.Operator]spec.SignedProof{
				fixtures.GenerateOperators(4)[0]: fixtures.TestOperator1Proof4Operators,
				fixtures.GenerateOperators(4)[1]: fixtures.TestOperator2Proof4Operators,
				fixtures.GenerateOperators(4)[2]: fixtures.TestOperator3Proof4Operators,
				fixtures.GenerateOperators(4)[3]: fixtures.TestOperator4Proof4Operators,
			},
		))
	})

	t.Run("valid 7 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateReshareMessage(
			fixtures.TestReshare7Operators,
			map[*spec.Operator]spec.SignedProof{
				fixtures.GenerateOperators(7)[0]: fixtures.TestOperator1Proof7Operators,
				fixtures.GenerateOperators(7)[1]: fixtures.TestOperator2Proof7Operators,
				fixtures.GenerateOperators(7)[2]: fixtures.TestOperator3Proof7Operators,
				fixtures.GenerateOperators(7)[3]: fixtures.TestOperator4Proof7Operators,
				fixtures.GenerateOperators(7)[4]: fixtures.TestOperator5Proof7Operators,
				fixtures.GenerateOperators(7)[5]: fixtures.TestOperator6Proof7Operators,
				fixtures.GenerateOperators(7)[6]: fixtures.TestOperator7Proof7Operators,
			},
		))
	})

	t.Run("valid 10 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateReshareMessage(
			fixtures.TestReshare10Operators,
			map[*spec.Operator]spec.SignedProof{
				fixtures.GenerateOperators(10)[0]: fixtures.TestOperator1Proof10Operators,
				fixtures.GenerateOperators(10)[1]: fixtures.TestOperator2Proof10Operators,
				fixtures.GenerateOperators(10)[2]: fixtures.TestOperator3Proof10Operators,
				fixtures.GenerateOperators(10)[3]: fixtures.TestOperator4Proof10Operators,
				fixtures.GenerateOperators(10)[4]: fixtures.TestOperator5Proof10Operators,
				fixtures.GenerateOperators(10)[5]: fixtures.TestOperator6Proof10Operators,
				fixtures.GenerateOperators(10)[6]: fixtures.TestOperator7Proof10Operators,
				fixtures.GenerateOperators(10)[7]: fixtures.TestOperator8Proof10Operators,
				fixtures.GenerateOperators(10)[8]: fixtures.TestOperator9Proof10Operators,
				fixtures.GenerateOperators(10)[9]: fixtures.TestOperator10Proof10Operators,
			},
		))
	})

	t.Run("valid 13 operators", func(t *testing.T) {
		require.NoError(t, spec.ValidateReshareMessage(
			fixtures.TestReshare13Operators,
			map[*spec.Operator]spec.SignedProof{
				fixtures.GenerateOperators(13)[0]:  fixtures.TestOperator1Proof13Operators,
				fixtures.GenerateOperators(13)[1]:  fixtures.TestOperator2Proof13Operators,
				fixtures.GenerateOperators(13)[2]:  fixtures.TestOperator3Proof13Operators,
				fixtures.GenerateOperators(13)[3]:  fixtures.TestOperator4Proof13Operators,
				fixtures.GenerateOperators(13)[4]:  fixtures.TestOperator5Proof13Operators,
				fixtures.GenerateOperators(13)[5]:  fixtures.TestOperator6Proof13Operators,
				fixtures.GenerateOperators(13)[6]:  fixtures.TestOperator7Proof13Operators,
				fixtures.GenerateOperators(13)[7]:  fixtures.TestOperator8Proof13Operators,
				fixtures.GenerateOperators(13)[8]:  fixtures.TestOperator9Proof13Operators,
				fixtures.GenerateOperators(13)[9]:  fixtures.TestOperator10Proof13Operators,
				fixtures.GenerateOperators(13)[10]: fixtures.TestOperator11Proof13Operators,
				fixtures.GenerateOperators(13)[11]: fixtures.TestOperator12Proof13Operators,
				fixtures.GenerateOperators(13)[12]: fixtures.TestOperator13Proof13Operators,
			},
		))
	})
}
