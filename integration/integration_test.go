package integration

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"github.com/pkg/errors"
	"net/http"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	ourcrypto "github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"
)

const encryptedKeyLength = 256

const exmaplePath = "../examples/"

type testServer struct {
	id      uint64
	privKey *rsa.PrivateKey
	srv     *server.Server
}

func CreateServer(t *testing.T, id uint64) *testServer {
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	srv := server.New(priv)

	return &testServer{
		id:      id,
		privKey: priv,
		srv:     srv,
	}
}

func TestHappyFlow4(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	ops := make(map[uint64]client.Operator)
	logger.Infof("Starting intg test")

	srv1 := CreateServer(t, 1)
	ops[1] = client.Operator{"http://localhost:3030", 1, &srv1.privKey.PublicKey}
	srv2 := CreateServer(t, 2)
	ops[2] = client.Operator{"http://localhost:3031", 2, &srv2.privKey.PublicKey}
	srv3 := CreateServer(t, 3)
	ops[3] = client.Operator{"http://localhost:3032", 3, &srv3.privKey.PublicKey}
	srv4 := CreateServer(t, 4)
	ops[4] = client.Operator{"http://localhost:3033", 4, &srv4.privKey.PublicKey}

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.srv.Start(3030)
	})
	eg.Go(func() error {
		return srv2.srv.Start(3031)
	})
	eg.Go(func() error {
		return srv3.srv.Start(3032)
	})
	eg.Go(func() error {
		return srv4.srv.Start(3033)
	})

	logger.Infof("Servers Started")
	clnt := client.New(ops)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")

	withdraw := newEthAddress(t)
	owner := newEthAddress(t)

	depositData, ks, err := clnt.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
	require.NoError(t, err)
	sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
	require.NoError(t, err)

	pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
	require.NoError(t, err)

	testSharesData(t, []*rsa.PrivateKey{srv1.privKey, srv2.privKey, srv3.privKey, srv4.privKey}, sharesDataSigned, pubkeyraw, owner, 0)

	testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
	srv1.srv.Stop()
	srv2.srv.Stop()
	srv3.srv.Stop()
	srv4.srv.Stop()

	require.ErrorIs(t, http.ErrServerClosed, eg.Wait())
}

func TestHappyFlow7(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	ops := make(map[uint64]client.Operator)
	logger.Infof("Starting intg test")

	srv1 := CreateServer(t, 1)
	ops[1] = client.Operator{"http://localhost:3030", 1, &srv1.privKey.PublicKey}
	srv2 := CreateServer(t, 2)
	ops[2] = client.Operator{"http://localhost:3031", 2, &srv2.privKey.PublicKey}
	srv3 := CreateServer(t, 3)
	ops[3] = client.Operator{"http://localhost:3032", 3, &srv3.privKey.PublicKey}
	srv4 := CreateServer(t, 4)
	ops[4] = client.Operator{"http://localhost:3033", 4, &srv4.privKey.PublicKey}
	srv5 := CreateServer(t, 5)
	ops[5] = client.Operator{"http://localhost:3034", 5, &srv5.privKey.PublicKey}
	srv6 := CreateServer(t, 6)
	ops[6] = client.Operator{"http://localhost:3035", 6, &srv6.privKey.PublicKey}
	srv7 := CreateServer(t, 7)
	ops[7] = client.Operator{"http://localhost:3036", 7, &srv7.privKey.PublicKey}

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.srv.Start(3030)
	})
	eg.Go(func() error {
		return srv2.srv.Start(3031)
	})
	eg.Go(func() error {
		return srv3.srv.Start(3032)
	})
	eg.Go(func() error {
		return srv4.srv.Start(3033)
	})
	eg.Go(func() error {
		return srv5.srv.Start(3034)
	})
	eg.Go(func() error {
		return srv6.srv.Start(3035)
	})
	eg.Go(func() error {
		return srv7.srv.Start(3036)
	})
	logger.Infof("Servers Started")
	clnt := client.New(ops)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")

	withdraw := newEthAddress(t)
	owner := newEthAddress(t)

	depositData, ks, err := clnt.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7}, 6, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
	require.NoError(t, err)
	sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
	require.NoError(t, err)

	pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
	require.NoError(t, err)

	testSharesData(t, []*rsa.PrivateKey{srv1.privKey, srv2.privKey, srv3.privKey, srv4.privKey, srv5.privKey, srv6.privKey, srv7.privKey}, sharesDataSigned, pubkeyraw, owner, 0)

	testDepositData(t, depositData, withdraw.Bytes(), owner, 0)

	srv1.srv.Stop()
	srv2.srv.Stop()
	srv3.srv.Stop()
	srv4.srv.Stop()
	srv5.srv.Stop()
	srv6.srv.Stop()
	srv7.srv.Stop()

	require.ErrorIs(t, http.ErrServerClosed, eg.Wait())
}

func TestHappyFlow12(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())
	ops := make(map[uint64]client.Operator)
	logger.Infof("Starting intg test")

	srv1 := CreateServer(t, 1)
	ops[1] = client.Operator{"http://localhost:3030", 1, &srv1.privKey.PublicKey}
	srv2 := CreateServer(t, 2)
	ops[2] = client.Operator{"http://localhost:3031", 2, &srv2.privKey.PublicKey}
	srv3 := CreateServer(t, 3)
	ops[3] = client.Operator{"http://localhost:3032", 3, &srv3.privKey.PublicKey}
	srv4 := CreateServer(t, 4)
	ops[4] = client.Operator{"http://localhost:3033", 4, &srv4.privKey.PublicKey}
	srv5 := CreateServer(t, 5)
	ops[5] = client.Operator{"http://localhost:3034", 5, &srv5.privKey.PublicKey}
	srv6 := CreateServer(t, 6)
	ops[6] = client.Operator{"http://localhost:3035", 6, &srv6.privKey.PublicKey}
	srv7 := CreateServer(t, 7)
	ops[7] = client.Operator{"http://localhost:3036", 7, &srv7.privKey.PublicKey}
	srv8 := CreateServer(t, 8)
	ops[8] = client.Operator{"http://localhost:3037", 8, &srv8.privKey.PublicKey}
	srv9 := CreateServer(t, 9)
	ops[9] = client.Operator{"http://localhost:3038", 9, &srv9.privKey.PublicKey}
	srv10 := CreateServer(t, 10)
	ops[10] = client.Operator{"http://localhost:3039", 10, &srv10.privKey.PublicKey}
	srv11 := CreateServer(t, 11)
	ops[11] = client.Operator{"http://localhost:30310", 11, &srv11.privKey.PublicKey}
	srv12 := CreateServer(t, 12)
	ops[12] = client.Operator{"http://localhost:30311", 12, &srv12.privKey.PublicKey}

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.srv.Start(3030)
	})
	eg.Go(func() error {
		return srv2.srv.Start(3031)
	})
	eg.Go(func() error {
		return srv3.srv.Start(3032)
	})
	eg.Go(func() error {
		return srv4.srv.Start(3033)
	})
	eg.Go(func() error {
		return srv5.srv.Start(3034)
	})
	eg.Go(func() error {
		return srv6.srv.Start(3035)
	})
	eg.Go(func() error {
		return srv7.srv.Start(3036)
	})
	eg.Go(func() error {
		return srv8.srv.Start(3037)
	})
	eg.Go(func() error {
		return srv9.srv.Start(3038)
	})
	eg.Go(func() error {
		return srv10.srv.Start(3039)
	})
	eg.Go(func() error {
		return srv11.srv.Start(30310)
	})
	eg.Go(func() error {
		return srv12.srv.Start(30311)
	})
	logger.Infof("Servers Started")
	clnt := client.New(ops)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")

	withdraw := newEthAddress(t)
	owner := newEthAddress(t)

	depositData, ks, err := clnt.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, 9, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
	require.NoError(t, err)
	sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
	require.NoError(t, err)

	pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
	require.NoError(t, err)

	testSharesData(t, []*rsa.PrivateKey{srv1.privKey, srv2.privKey, srv3.privKey, srv4.privKey, srv5.privKey, srv6.privKey, srv7.privKey, srv8.privKey, srv9.privKey, srv10.privKey, srv11.privKey, srv12.privKey}, sharesDataSigned, pubkeyraw, owner, 0)

	testDepositData(t, depositData, withdraw.Bytes(), owner, 0)

	srv1.srv.Stop()
	srv2.srv.Stop()
	srv3.srv.Stop()
	srv4.srv.Stop()
	srv5.srv.Stop()
	srv6.srv.Stop()
	srv7.srv.Stop()
	srv8.srv.Stop()
	srv9.srv.Stop()
	srv10.srv.Stop()
	srv11.srv.Stop()
	srv12.srv.Stop()

	require.ErrorIs(t, http.ErrServerClosed, eg.Wait())
}

func testSharesData(t *testing.T, keys []*rsa.PrivateKey, sharesData []byte, validatorPublicKey []byte, owner common.Address, nonce uint16) {
	operatorCount := len(keys)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := encryptedKeyLength*operatorCount + pubKeysOffset

	require.Len(t, sharesData, sharesExpectedLength)

	signature := sharesData[:signatureOffset]

	msg := []byte("Hello")

	require.NoError(t, ourcrypto.VerifyOwnerNoceSignature(signature, owner, validatorPublicKey, nonce))

	_ = splitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := splitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)

	sigs2 := make(map[uint64][]byte)

	for i, enck := range encryptedKeys {
		priv := keys[i]
		share, err := rsaencryption.DecodeKey(priv, enck)
		require.NoError(t, err)
		secret := &bls.SecretKey{}
		require.NoError(t, secret.SetHexString(string(share)))

		sig := secret.SignByte(msg)
		sigs2[uint64(i+1)] = sig.Serialize()
	}

	recon, err := ReconstructSignatures(sigs2)
	require.NoError(t, err)

	require.NoError(t, VerifyReconstructedSignature(recon, validatorPublicKey, msg))

}

// ReconstructSignatures receives a map of user indexes and serialized bls.Sign.
// It then reconstructs the original threshold signature using lagrange interpolation
func ReconstructSignatures(signatures map[uint64][]byte) (*bls.Sign, error) {
	reconstructedSig := bls.Sign{}

	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)

	for index, signature := range signatures {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", index))
		if err != nil {
			return nil, err
		}

		idVec = append(idVec, blsID)
		blsSig := bls.Sign{}

		err = blsSig.Deserialize(signature)
		if err != nil {
			return nil, err
		}

		sigVec = append(sigVec, blsSig)
	}
	err := reconstructedSig.Recover(sigVec, idVec)
	return &reconstructedSig, err
}

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey []byte, msg []byte) error {
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(validatorPubKey); err != nil {
		return errors.Wrap(err, "could not deserialize validator pk")
	}

	// verify reconstructed sig
	if res := sig.VerifyByte(pk, msg); !res {
		return errors.New("could not reconstruct a valid signature")
	}
	return nil
}

func newEthAddress(t *testing.T) common.Address {
	privateKey, err := eth_crypto.GenerateKey()
	require.NoError(t, err)

	//privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	//publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	address := eth_crypto.PubkeyToAddress(*publicKeyECDSA)

	return address
}

func splitBytes(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func testDepositData(t *testing.T, depsitDataJson *client.DepositDataJson, withdrawCred []byte, owner common.Address, nonce uint16) {
	require.True(t, bytes.Equal(crypto.WithdrawalCredentialsHash(withdrawCred), hexutil.MustDecode("0x"+depsitDataJson.WithdrawalCredentials)))
	masterSig := &bls.Sign{}
	require.NoError(t, masterSig.DeserializeHexStr(depsitDataJson.Signature))
	valdatorPubKey := &bls.PublicKey{}
	require.NoError(t, valdatorPubKey.DeserializeHexStr(depsitDataJson.PubKey))

	// Check root
	var fork [4]byte
	copy(fork[:], hexutil.MustDecode("0x"+depsitDataJson.ForkVersion))
	depositDataRoot, err := ourcrypto.DepositDataRoot(withdrawCred, valdatorPubKey, dkg.GetNetworkByFork(fork), client.MaxEffectiveBalanceInGwei)
	require.NoError(t, err)
	res := masterSig.VerifyByte(valdatorPubKey, depositDataRoot[:])
	require.True(t, res)
	depositData, _, err := ourcrypto.DepositData(masterSig.Serialize(), withdrawCred, valdatorPubKey.Serialize(), dkg.GetNetworkByFork(fork), client.MaxEffectiveBalanceInGwei)
	require.NoError(t, err)
	res, err = crypto.VerifyDepositData(depositData, dkg.GetNetworkByFork(fork))
	require.NoError(t, err)
	require.True(t, res)
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                client.MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, _ := depositMsg.HashTreeRoot()
	require.True(t, bytes.Equal(depositMsgRoot[:], hexutil.MustDecode("0x"+depsitDataJson.DepositMessageRoot)))
}
