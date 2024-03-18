package fixtures

import "github.com/bloxapp/ssv-dkg/pkgs/wire"

var (
	TestReshare4Operators = wire.Reshare{
		ValidatorPubKey: ShareSK(TestValidator4Operators).GetPublicKey().Serialize(),
		OldOperators:    GenerateOperators(4),
		NewOperators: []*wire.Operator{
			GenerateOperators(4)[0],
			GenerateOperators(4)[1],
			GenerateOperators(4)[2],
			GenerateOperators(7)[4],
		},
		OldT:  3,
		NewT:  3,
		Owner: TestOwnerAddress,
		Nonce: 1,
	}
	TestReshare7Operators = wire.Reshare{
		ValidatorPubKey: ShareSK(TestValidator7Operators).GetPublicKey().Serialize(),
		OldOperators:    GenerateOperators(7),
		NewOperators: []*wire.Operator{
			GenerateOperators(7)[0],
			GenerateOperators(7)[1],
			GenerateOperators(7)[2],
			GenerateOperators(7)[3],
			GenerateOperators(7)[4],
			GenerateOperators(7)[5],
			GenerateOperators(10)[7],
		},
		OldT:  5,
		NewT:  5,
		Owner: TestOwnerAddress,
		Nonce: 1,
	}
	TestReshare10Operators = wire.Reshare{
		ValidatorPubKey: ShareSK(TestValidator10Operators).GetPublicKey().Serialize(),
		OldOperators:    GenerateOperators(10),
		NewOperators: []*wire.Operator{
			GenerateOperators(10)[0],
			GenerateOperators(10)[1],
			GenerateOperators(10)[2],
			GenerateOperators(10)[3],
			GenerateOperators(10)[4],
			GenerateOperators(10)[5],
			GenerateOperators(10)[6],
			GenerateOperators(10)[7],
			GenerateOperators(10)[8],
			GenerateOperators(13)[10],
		},
		OldT:  7,
		NewT:  7,
		Owner: TestOwnerAddress,
		Nonce: 1,
	}
	TestReshare13Operators = wire.Reshare{
		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
		OldOperators:    GenerateOperators(13),
		NewOperators: []*wire.Operator{
			GenerateOperators(13)[0],
			GenerateOperators(13)[1],
			GenerateOperators(13)[2],
			GenerateOperators(13)[3],
			GenerateOperators(13)[4],
			GenerateOperators(13)[5],
			GenerateOperators(13)[6],
			GenerateOperators(13)[7],
			GenerateOperators(13)[8],
			GenerateOperators(13)[9],
			GenerateOperators(13)[10],
			GenerateOperators(13)[11],
			{
				ID:     14,
				PubKey: EncodedOperatorPK(TestOperator14SK),
			},
		},
		OldT:  9,
		NewT:  9,
		Owner: TestOwnerAddress,
		Nonce: 1,
	}
)
