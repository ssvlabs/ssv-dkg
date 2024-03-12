package testing

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

func TestDDDD(t *testing.T) {
	// master key Polynomial
	msk := make([]bls.SecretKey, 10)

	sk := &bls.SecretKey{}
	sk.SetByCSPRNG()
	msk[0] = *sk

	// construct poly
	for i := uint64(1); i < 10; i++ {
		sk := bls.SecretKey{}
		sk.SetByCSPRNG()
		msk[i] = sk
	}

	ids := []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13}

	// evaluate shares - starting from 1 because 0 is master key
	shares := make(map[uint64]*bls.SecretKey)
	for i := uint64(0); i < 13; i++ {
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

		shares[uint64(id)] = &sk
	}

	fmt.Printf("validator sk: %s\n", sk.GetHexString())
	fmt.Printf("share sk 1: %s\n", shares[1].GetHexString())
	fmt.Printf("share sk 2: %s\n", shares[2].GetHexString())
	fmt.Printf("share sk 3: %s\n", shares[3].GetHexString())
	fmt.Printf("share sk 4: %s\n", shares[4].GetHexString())
	fmt.Printf("share sk 5: %s\n", shares[5].GetHexString())
	fmt.Printf("share sk 6: %s\n", shares[6].GetHexString())
	fmt.Printf("share sk 7: %s\n", shares[7].GetHexString())
	fmt.Printf("share sk 8: %s\n", shares[8].GetHexString())
	fmt.Printf("share sk 9: %s\n", shares[9].GetHexString())
	fmt.Printf("share sk 10: %s\n", shares[10].GetHexString())
	fmt.Printf("share sk 1: %s\n", shares[11].GetHexString())
	fmt.Printf("share sk 12: %s\n", shares[12].GetHexString())
	fmt.Printf("share sk 13: %s\n", shares[13].GetHexString())

}

func TestSignNonce(t *testing.T) {
	data := fmt.Sprintf("%s:%d", common.Address(TestOwnerAddress).String(), TestNonce)
	hash := eth_crypto.Keccak256([]byte(data))

	sig := shareSK(TestValidator13OperatorsShare1).SignByte(hash[:])
	fmt.Printf("%x\n", sig.Serialize())
}

func TestSignDeposit(t *testing.T) {
	network, err := utils.GetNetworkByFork(TestFork)
	require.NoError(t, err)
	shareRoot, err := crypto.ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             phase0.BLSPubKey(shareSK(TestValidator13Operators).GetPublicKey().Serialize()),
		Amount:                dkg.MaxEffectiveBalanceInGwei,
		WithdrawalCredentials: crypto.ETH1WithdrawalCredentials(TestWithdrawalCred)})
	require.NoError(t, err)

	sig := shareSK(TestValidator13OperatorsShare1).SignByte(shareRoot[:])
	fmt.Printf("%x\n", sig.Serialize())
}

func TestProof(t *testing.T) {
	proof := &spec.Proof{
		ValidatorPubKey: shareSK(TestValidator13Operators).GetPublicKey().Serialize(),
		EncryptedShare:  DecodeHexNoError(TestValidator13OperatorsShare1),
		SharePubKey:     shareSK(TestValidator13OperatorsShare1).GetPublicKey().Serialize(),
		Owner:           TestOwnerAddress,
	}

	r, _ := proof.HashTreeRoot()

	sig, err := crypto.SignRSA(operatorSK(TestOperator1SK), r[:])
	require.NoError(t, err)
	fmt.Printf("%x\n", sig)
}

func TestDdD(t *testing.T) {
	sk := shareSK(TestValidator4OperatorsShare1)
	fmt.Printf("%s\n", sk.GetHexString())
}

func TestDD(t *testing.T) {
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
