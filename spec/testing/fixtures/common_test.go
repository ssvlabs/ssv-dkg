package fixtures

import (
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/spec"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"
	"testing"
)

func TestSSS(t *testing.T) {
	// master key Polynomial
	msk := make([]bls.SecretKey, 10)

	sk := &bls.SecretKey{}
	//sk.SetByCSPRNG()
	sk.SetHexString(TestValidator10Operators)
	msk[0] = *sk

	// construct poly
	for i := uint64(1); i < 7; i++ {
		sk := bls.SecretKey{}
		sk.SetByCSPRNG()
		msk[i] = sk
	}

	ids := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10}

	// evaluate shares - starting from 1 because 0 is master key
	shares := make(map[uint64]*bls.SecretKey)
	for i := uint64(0); i < 10; i++ {
		id := ids[i]
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", id))
		if err != nil {
			panic(err)
		}

		sk := bls.SecretKey{}

		err = sk.Set(msk, &blsID)
		if err != nil {
			panic(err)
		}

		fmt.Printf("share %d sk: %s\n", id, sk.GetHexString())

		shares[uint64(id)] = &sk
	}

	fmt.Printf("validator sk: %s\n", sk.GetHexString())

}

func TestSignNonce(t *testing.T) {
	data := fmt.Sprintf("%s:%d", common.Address(TestOwnerAddress).String(), TestNonce)
	hash := eth_crypto.Keccak256([]byte(data))

	sig := ShareSK(TestValidator13OperatorsShare1).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare2).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare3).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare4).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare5).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare6).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare7).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare8).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare9).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare10).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare11).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare12).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare13).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
}

func TestSignDeposit(t *testing.T) {
	network, err := utils.GetNetworkByFork(TestFork)
	require.NoError(t, err)
	shareRoot, err := crypto.ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(ShareSK(TestValidator13Operators).GetPublicKey().Serialize()),
		Amount:                dkg.MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: crypto.ETH1WithdrawalCredentials(TestWithdrawalCred)})
	require.NoError(t, err)

	sig := ShareSK(TestValidator13OperatorsShare1).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare2).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare3).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare4).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare5).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare6).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare7).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare8).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare9).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare10).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare11).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare12).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
	sig = ShareSK(TestValidator13OperatorsShare13).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
}

func TestProof(t *testing.T) {
	proof := &spec.Proof{
		ValidatorPubKey: ShareSK(TestValidator13Operators).GetPublicKey().Serialize(),
		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsEncShare13),
		SharePubKey:     ShareSK(TestValidator13OperatorsShare13).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
	}

	r, _ := proof.HashTreeRoot()

	sig, err := crypto.SignRSA(OperatorSK(TestOperator13SK), r[:])
	require.NoError(t, err)
	fmt.Printf("%x\n", sig)
}

func TestEncryptShare(t *testing.T) {
	cypher, err := crypto.Encrypt(&OperatorSK(TestOperator1SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare1))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator2SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare2))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator3SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare3))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator4SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare4))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator5SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare5))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator6SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare6))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator7SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare7))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator8SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare8))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator9SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare9))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator10SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare10))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator11SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare11))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator12SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare12))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
	cypher, err = crypto.Encrypt(&OperatorSK(TestOperator13SK).PublicKey, DecodeHexNoError(TestValidator13OperatorsShare13))
	require.NoError(t, err)
	fmt.Printf("%x\n", cypher)
}

func TestDdD(t *testing.T) {
	sk := ShareSK(TestValidator4OperatorsShare1)
	fmt.Printf("%s\n", sk.GetHexString())
}

func TestOperatorSK(t *testing.T) {
	sk, _, _ := crypto.GenerateKeys()
	byts := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(sk),
		},
	)
	fmt.Printf("%x\n", byts)

}

func TestHH(t *testing.T) {
	byts, _ := hex.DecodeString(TestOperator1SK)
	blk, _ := pem.Decode(byts)

	priv, _ := x509.ParsePKCS1PrivateKey(blk.Bytes)

	byts = pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(priv),
		},
	)
	fmt.Printf("%x\n", byts)
}
