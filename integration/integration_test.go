package integration

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	ourcrypto "github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
	"net/http"
	"testing"
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

func TestEverything(t *testing.T) {
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

	_, ks, err := clnt.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
	sharesDataSigned, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
	require.NoError(t, err)

	pubkeyraw, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
	require.NoError(t, err)

	testSharesData(t, []*rsa.PrivateKey{srv1.privKey, srv2.privKey, srv3.privKey, srv4.privKey}, sharesDataSigned, pubkeyraw, owner, 0)

	// todo: @pavel verify depositdata

	srv1.srv.Stop()
	srv2.srv.Stop()
	srv3.srv.Stop()
	srv4.srv.Stop()

	require.ErrorIs(t, http.ErrServerClosed, eg.Wait())
}
func testSharesData(t *testing.T, keys []*rsa.PrivateKey, sharesData []byte, validatorPublicKey []byte, owner common.Address, nonce uint16) {
	operatorCount := 4
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := encryptedKeyLength*operatorCount + pubKeysOffset

	require.Len(t, sharesData, sharesExpectedLength)

	signature := sharesData[:signatureOffset]

	require.NoError(t, ourcrypto.VerifyOwnerNoceSignature(signature, owner, validatorPublicKey, nonce))

	_ = splitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := splitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)

	for i, enck := range encryptedKeys {
		priv := keys[i]
		_, err := rsaencryption.DecodeKey(priv, enck)
		require.NoError(t, err)
	}
}
func newEthAddress(t *testing.T) common.Address {
	privateKey, err := crypto.GenerateKey()
	require.NoError(t, err)

	//privateKeyBytes := crypto.FromECDSA(privateKey)

	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)

	//publicKeyBytes := crypto.FromECDSAPub(publicKeyECDSA)

	address := crypto.PubkeyToAddress(*publicKeyECDSA)

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
