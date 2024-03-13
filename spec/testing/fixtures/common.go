package fixtures

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/spec"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
)

var (
	TestWithdrawalCred = make([]byte, 40)
	TestFork           = [4]byte{0, 0, 0, 0}
	TestNonce          = uint64(0)
	TestOwnerAddress   = common.Address{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20}
	TestRequestID      = [24]byte{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18, 19, 20, 21, 22, 23, 24}
)

func GenerateOperators(amount int) []*spec.Operator {
	ret := []*spec.Operator{
		{
			ID:     1,
			PubKey: EncodedOperatorPK(TestOperator1SK),
		},
		{
			ID:     2,
			PubKey: EncodedOperatorPK(TestOperator2SK),
		},
		{
			ID:     3,
			PubKey: EncodedOperatorPK(TestOperator3SK),
		},
		{
			ID:     4,
			PubKey: EncodedOperatorPK(TestOperator4SK),
		},
	}

	if amount > 4 {
		ret = append(ret, []*spec.Operator{
			{
				ID:     5,
				PubKey: EncodedOperatorPK(TestOperator5SK),
			},
			{
				ID:     6,
				PubKey: EncodedOperatorPK(TestOperator6SK),
			},
			{
				ID:     7,
				PubKey: EncodedOperatorPK(TestOperator7SK),
			},
		}...)
	}

	if amount > 7 {
		ret = append(ret, []*spec.Operator{
			{
				ID:     8,
				PubKey: EncodedOperatorPK(TestOperator8SK),
			},
			{
				ID:     9,
				PubKey: EncodedOperatorPK(TestOperator9SK),
			},
			{
				ID:     10,
				PubKey: EncodedOperatorPK(TestOperator10SK),
			},
		}...)
	}

	if amount > 10 {
		ret = append(ret, []*spec.Operator{
			{
				ID:     11,
				PubKey: EncodedOperatorPK(TestOperator11SK),
			},
			{
				ID:     12,
				PubKey: EncodedOperatorPK(TestOperator12SK),
			},
			{
				ID:     13,
				PubKey: EncodedOperatorPK(TestOperator13SK),
			},
		}...)
	}

	return ret
}

func OperatorSK(str string) *rsa.PrivateKey {
	byts, _ := hex.DecodeString(str)
	blk, _ := pem.Decode(byts)

	priv, _ := x509.ParsePKCS1PrivateKey(blk.Bytes)
	return priv
}

func EncodedOperatorPK(str string) []byte {
	ret, _ := crypto.EncodePublicKey(&OperatorSK(str).PublicKey)
	return ret
}

func ShareSK(str string) *bls.SecretKey {
	ret := &bls.SecretKey{}
	ret.SetHexString(str)
	return ret
}

func DecodeHexNoError(str string) []byte {
	ret, err := hex.DecodeString(str)
	if err != nil {
		panic(err)
	}
	return ret
}
