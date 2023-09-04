package client_test

import (
	"crypto/ecdsa"
	"fmt"
	"testing"
	"time"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client/test_server"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client/test_server/dkg"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

// TODO: use mocks instead of servers

const operatorsMetaData = `[
	{
	  "id": 1,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3030"
	},
	{
	  "id": 2,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdnRVRWFlallqY3pBUWhnSTQ0S3cKcGZYZjhCNk1ZUjhOMzFmRVFLRGRDVmo5dUNPcHVybzYzSDdxWXNzMzVGaVdxNmRwMjR3M0dCRTAzR1llU1BSZgowTEVBVEJkYlhCVkY3WGR6ei9sV2UrblJNRG1Xdm1DTUZjRlRPRU5FYmhuTXVjOEQ1K3ZFTmo5cTQzbE4vejhqCmE2T2M4S2tEL2E4SW02Nm54ZkRhMjFyMzNaSW9GL1g5d0g2K25EN3Jockx5bzJub1lxaVJpT1NTTkp2R25UY08KazBmckk4b2xFNjR1clhxWXFLN2ZicXNaN082NnphN2ROTmc3MW1EWHlpdDlSTUlyR3lSME5xN0FUSkxwbytoTApEcldoY0h4M0NWb1dQZzNuR2phN0duVFhXU2FWb1JPSnBRVU9oYXgxNVJnZ2FBOHpodGgyOUorNnNNY2R6ZitQCkZ3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3031"
	},
	{
	  "id": 3,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdlFhZlo0ODJQYXRsYnRrOVdIb2MKZDBWdWNWWDk4QUlzenAvazlFTlYyQU82SVhQUXVqU1BtdUZrQTlibThsSllnWTJPb0lQU0RmK1JHWGNMc2R0VApzdEJhQ2JPL0pMOFlSejk4NURKejhBRlhDU0J3bW5mbzROSFptUjJGMVdMTE5CS2wzdVQ5Q1VLbC9RUnpKRFF1CjNNYVJ6eE5FVmdONWtvU1Nid0NxVDNDSCtjam5QU0pIeGhiaTNTaldOSnJFb3ZRUmN3ZUlpYXRrZEdVNWJOUkoKUW1LVldhYzhzVklYN2NDNE54V2RDNG1VM1RPK2Vlei90N2xVcnhSNjdnb21TbGdwaU5weFJ1M2dFajRkSWpINwpsZDlTYW1ObEJPeHV5N0lFMEJpdm5nSUdIKzVwcXZVTXhoM0N5WkVtMjFHd3JTRFhqcVpwWG92OEUwQkQ5eGY4ClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3032"
	},
	{
	  "id": 4,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeFRWM2I5OHU4NmtzcEhQcWgrS2QKKzRHd0lSeEhwRHpEZjVlc3hjZytxaTlvbDRERmplUXMrbGloeUp5cGdOMXJwdTlQVnR5cXp2K3k5cEVNa0VXTgovYjBUQmdRMEp5TzdmNGliY1d5UUcrNGhVUS9XY3h1ZW5aUDA3S0VwTjh4Tk8xN3BzbmhRMXRqQVhybDNGN1lYCmlZdXl5Z0Rta2w0YjYrUDR6MjNhR01VSEtnTnJ5aFlZTFV4dWdycDVRTnJTV3lXNXFtb2EvYnJDenQ2RFJYb1UKU25JSkpSUVpPS2NnckdKMHVBYjJDRmtsL0xuaElxT2RZZ21aUG9oRmprVEorRnZNdkZsMjAwZ1BHbVpxUS9MMgpsM2ZBdmhZYlZRMlRVeUtmU2orYXZ1WUFZZnhKeG5OcWlmdkNkVGNmQzc3c0N0eFFERWVjY0pTVnVDbGZWeTFZCll3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3033"
	}
  ]`

const exmaplePath = "../../examples/"

func CreateTestServer(t *testing.T, id uint64) *test_server.Server {
	pk, err := load.EncryptedPrivateKey(exmaplePath+"server"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	srv := test_server.New(pk, nil)
	return srv
}

func CreateTestServerRandomKey(t *testing.T, id uint64) *test_server.Server {
	priv, _, err := crypto.GenerateKeys()
	require.NoError(t, err)
	srv := test_server.New(priv, nil)
	return srv
}

func CreateEveTestServer(t *testing.T, id uint64, eveCase *dkg.EveTest) *test_server.Server {
	pk, err := load.EncryptedPrivateKey(exmaplePath+"server"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	srv := test_server.New(pk, eveCase)
	return srv
}

func TestHappyFlow(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	srv1 := CreateTestServer(t, 1)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		err := srv1.Start(3030)
		require.NoError(t, err)
		return err
	})
	eg.Go(func() error {
		err := srv2.Start(3031)
		require.NoError(t, err)
		return err
	})
	eg.Go(func() error {
		err := srv3.Start(3032)
		require.NoError(t, err)
		return err
	})
	eg.Go(func() error {
		err := srv4.Start(3033)
		require.NoError(t, err)
		return err
	})

	logger.Infof("Servers Started")

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")

	withdraw := newEthAddress(t)
	owner := newEthAddress(t)

	_, _, err = clnt.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
	require.NoError(t, err)
}

func TestWrongServerKey(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	srv1 := CreateTestServerRandomKey(t, 1)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.Start(3030)
	})
	eg.Go(func() error {
		return srv2.Start(3031)
	})
	eg.Go(func() error {
		return srv3.Start(3032)
	})
	eg.Go(func() error {
		return srv4.Start(3033)
	})

	logger.Infof("Servers Started")

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")

	_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
	require.ErrorContains(t, err, "my operator is missing inside the op list")
}

func TestWrongPartialSignatures(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	eveMsg := dkg.EveTest{
		WrongPartialSig: "0x87912f24669427628885cf0b70385b94694951626805ff565f4d2a0b74c433a45b279769ff23c23c8dd4ae3625fa06c20df368c0dc24931f3ebe133b3e1fed7d3477c51fa291e61052b0286c7fc453bb5e10346c43eadda9ef1bac8db14acda4",
	}

	srv1 := CreateEveTestServer(t, 1, &eveMsg)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.Start(3030)
	})
	eg.Go(func() error {
		return srv2.Start(3031)
	})
	eg.Go(func() error {
		return srv3.Start(3032)
	})
	eg.Go(func() error {
		return srv4.Start(3033)
	})

	logger.Infof("Servers Started")

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
	require.ErrorContains(t, err, "error verifying partial deposit signature")
}

func TestWrongID(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	eveMsg := dkg.EveTest{
		WrongID: "0x0000000000000000630ab8af69364a6db7b6d7d59bb60f23",
	}

	srv1 := CreateEveTestServer(t, 1, &eveMsg)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.Start(3030)
	})
	eg.Go(func() error {
		return srv2.Start(3031)
	})
	eg.Go(func() error {
		return srv3.Start(3032)
	})
	eg.Go(func() error {
		return srv4.Start(3033)
	})

	logger.Infof("Servers Started")

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
	require.ErrorContains(t, err, "DKG result has wrong ID")
}

func TestOperatorTimeout(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	eveMsg := dkg.EveTest{
		Timeout: time.Second * 30,
	}

	srv1 := CreateEveTestServer(t, 1, &eveMsg)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.Start(3030)
	})
	eg.Go(func() error {
		return srv2.Start(3031)
	})
	eg.Go(func() error {
		return srv3.Start(3032)
	})
	eg.Go(func() error {
		return srv4.Start(3033)
	})

	logger.Infof("Servers Started")

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
	require.ErrorContains(t, err, "Client.Timeout exceeded while awaiting headers")
}

func TestWrongThreshold(t *testing.T) {
	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)
	clnt := client.New(opmap)
	_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, 10, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
	require.ErrorContains(t, err, "wrong threshold")
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

// func TestHappyFlowMock(t *testing.T) {
// 	logger := logrus.NewEntry(logrus.New())

// 	logger.Infof("Starting intg test")

// 	srv1 := CreateTestServer(t, 1)
// 	srv2 := CreateTestServer(t, 2)
// 	srv3 := CreateTestServer(t, 3)
// 	srv4 := CreateTestServer(t, 4)

// 	logger.Infof("Servers created")

// 	eg := errgroup.Group{}
// 	eg.Go(func() error {
// 		err := srv1.Start(3030)
// 		require.NoError(t, err)
// 		return err
// 	})
// 	eg.Go(func() error {
// 		err := srv2.Start(3031)
// 		require.NoError(t, err)
// 		return err
// 	})
// 	eg.Go(func() error {
// 		err := srv3.Start(3032)
// 		require.NoError(t, err)
// 		return err
// 	})
// 	eg.Go(func() error {
// 		err := srv4.Start(3033)
// 		require.NoError(t, err)
// 		return err
// 	})

// 	logger.Infof("Servers Started")

// 	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
// 	require.NoError(t, err)

// 	mockCtrl := gomock.NewController(t)
// 	defer mockCtrl.Finish()
// 	mockClient := mocks.NewMockDKGClient(mockCtrl)

// 	c := req.C()
// 	// Set timeout for operator responses
// 	c.SetTimeout(30 * time.Second)
// 	client := &client.Client{
// 		Logger:    logrus.NewEntry(logrus.New()),
// 		Client:    c,
// 		Operators: opmap,
// 	}

// 	parts := make([]*wire.Operator, 0, 0)
// 	for _, id := range []uint64{1, 2, 3, 4} {
// 		op, ok := client.Operators[id]
// 		if !ok {
// 			t.FailNow()
// 		}
// 		pkBytes, err := crypto.EncodePublicKey(op.PubKey)
// 		require.NoError(t, err)
// 		parts = append(parts, &wire.Operator{
// 			ID:     op.ID,
// 			PubKey: pkBytes,
// 		})
// 	}
// 	// Add messages verification coming form operators
// 	verify, err := client.CreateVerifyFunc(parts)
// 	require.NoError(t, err)
// 	client.VerifyFunc = verify

// 	// make init message
// 	init := &wire.Init{
// 		Operators:             parts,
// 		T:                     3,
// 		WithdrawalCredentials: common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(),
// 		Fork:                  [4]byte{0, 0, 0, 0},
// 		Owner:                 common.HexToAddress("0x0000000000000000000000000000000000000007"),
// 		Nonce:                 0,
// 	}

// 	id := client.NewID()
// 	mockClient.EXPECT().SendInitMsg(init, id).Return(nil, fmt.Errorf("Test err")).Times(1)
// 	_, _, err = client.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
// 	require.NoError(t, err)
// }
