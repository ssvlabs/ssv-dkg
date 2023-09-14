package initiator_test

import (
	"crypto/ecdsa"
	"crypto/rsa"
	"fmt"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	mock_operator "github.com/bloxapp/ssv-dkg/pkgs/initiator/mock_operator"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator/mock_operator/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/load"
	operator "github.com/bloxapp/ssv-dkg/pkgs/operator"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

// TODO: use mocks instead of servers
type testOperator struct {
	id      uint64
	privKey *rsa.PrivateKey
	srv     *httptest.Server
}

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

func TestOperatorMisbehave(t *testing.T) {
	ops := make(map[uint64]initiator.Operator)
	srv2 := CreateTestOperator(t, 2)
	srv3 := CreateTestOperator(t, 3)
	srv4 := CreateTestOperator(t, 4)
	ops[2] = initiator.Operator{srv2.srv.URL, 2, &srv2.privKey.PublicKey}
	ops[3] = initiator.Operator{srv3.srv.URL, 3, &srv3.privKey.PublicKey}
	ops[4] = initiator.Operator{srv4.srv.URL, 4, &srv4.privKey.PublicKey}
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	t.Run("test wrong amount of opeators < 4", func(t *testing.T) {
		opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
		require.NoError(t, err)
		clnt := initiator.New(priv, opmap)
		_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
		require.ErrorContains(t, err, "minimum supported amount of operators is 4")
	})
	t.Run("test wrong amount of opeators > 13", func(t *testing.T) {
		opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
		require.NoError(t, err)
		clnt := initiator.New(priv, opmap)
		_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
		require.ErrorContains(t, err, "maximum supported amount of operators is 13")
	})
	t.Run("test opeators not unique", func(t *testing.T) {
		opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
		require.NoError(t, err)
		clnt := initiator.New(priv, opmap)
		_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 7, 9, 10, 11, 12, 12}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
		require.ErrorContains(t, err, "operators ids should be unique in the list")
	})
	t.Run("test wrong server key", func(t *testing.T) {
		srv1 := CreateTestOperatorRandomKey(t, 1)
		ops[1] = initiator.Operator{srv1.srv.URL, 1, &srv2.privKey.PublicKey}
		clnt := initiator.New(priv, ops)
		_, _, err := clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
		require.ErrorContains(t, err, "my operator is missing inside the op list")
		srv1.srv.Close()
	})

	t.Run("test wrong partial deposit signature", func(t *testing.T) {
		eveMsg := dkg.EveTest{
			WrongPartialSig: "0x87912f24669427628885cf0b70385b94694951626805ff565f4d2a0b74c433a45b279769ff23c23c8dd4ae3625fa06c20df368c0dc24931f3ebe133b3e1fed7d3477c51fa291e61052b0286c7fc453bb5e10346c43eadda9ef1bac8db14acda4",
		}
		srv1 := CreateEveTestOperator(t, 1, &eveMsg)
		ops[1] = initiator.Operator{srv1.srv.URL, 1, &srv1.privKey.PublicKey}
		clnt := initiator.New(priv, ops)
		_, _, err := clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
		require.ErrorContains(t, err, "error verifying partial deposit signature")
		srv1.srv.Close()
	})

	t.Run("test wrong request ID", func(t *testing.T) {
		eveMsg := dkg.EveTest{
			WrongID: "0x0000000000000000630ab8af69364a6db7b6d7d59bb60f23",
		}
		srv1 := CreateEveTestOperator(t, 1, &eveMsg)
		ops[1] = initiator.Operator{srv1.srv.URL, 1, &srv1.privKey.PublicKey}
		clnt := initiator.New(priv, ops)
		_, _, err := clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
		require.ErrorContains(t, err, "DKG result has wrong ID")
		srv1.srv.Close()
	})
	srv2.srv.Close()
	srv3.srv.Close()
	srv4.srv.Close()
}

func TestTimeout(t *testing.T) {
	ops := make(map[uint64]initiator.Operator)
	eveMsg := dkg.EveTest{
		Timeout: time.Second * 30,
	}
	srv1 := CreateEveTestOperator(t, 1, &eveMsg)
	srv2 := CreateTestOperator(t, 2)
	srv3 := CreateTestOperator(t, 3)
	srv4 := CreateTestOperator(t, 4)
	ops[1] = initiator.Operator{srv1.srv.URL, 1, &srv1.privKey.PublicKey}
	ops[2] = initiator.Operator{srv2.srv.URL, 2, &srv2.privKey.PublicKey}
	ops[3] = initiator.Operator{srv3.srv.URL, 3, &srv3.privKey.PublicKey}
	ops[4] = initiator.Operator{srv4.srv.URL, 4, &srv4.privKey.PublicKey}
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	clnt := initiator.New(priv, ops)
	_, _, err = clnt.StartDKG(common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", common.HexToAddress("0x0000000000000000000000000000000000000007"), 0)
	require.ErrorContains(t, err, "Client.Timeout exceeded while awaiting headers")
	srv1.srv.Close()
	srv2.srv.Close()
	srv3.srv.Close()
	srv4.srv.Close()
}
func CreateTestOperator(t *testing.T, id uint64) *testOperator {
	priv, err := load.EncryptedPrivateKey(exmaplePath+"server"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	r := chi.NewRouter()
	swtch := operator.NewSwitch(priv)
	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &operator.Server{
		Logger: logrus.NewEntry(lg).WithField("comp", "server"),
		Router: r,
		State:  swtch,
	}
	operator.RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &testOperator{
		id:      id,
		privKey: priv,
		srv:     sTest,
	}
}

func CreateTestOperatorRandomKey(t *testing.T, id uint64) *testOperator {
	priv, _, err := crypto.GenerateKeys()
	require.NoError(t, err)
	r := chi.NewRouter()
	swtch := operator.NewSwitch(priv)
	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &operator.Server{
		Logger: logrus.NewEntry(lg).WithField("comp", "server"),
		Router: r,
		State:  swtch,
	}
	operator.RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &testOperator{
		id:      id,
		privKey: priv,
		srv:     sTest,
	}
}

func CreateEveTestOperator(t *testing.T, id uint64, eveCase *dkg.EveTest) *testOperator {
	priv, err := load.EncryptedPrivateKey(exmaplePath+"server"+fmt.Sprintf("%v", id)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	r := chi.NewRouter()
	swtch := mock_operator.NewSwitch(priv)
	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &mock_operator.Server{
		Logger: logrus.NewEntry(lg).WithField("comp", "server"),
		Router: r,
		State:  swtch,
	}
	mock_operator.RegisterRoutes(s, eveCase)
	sTest := httptest.NewServer(s.Router)
	return &testOperator{
		id:      id,
		privKey: priv,
		srv:     sTest,
	}
}

func newEthAddress(t *testing.T) common.Address {
	privateKey, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	address := eth_crypto.PubkeyToAddress(*publicKeyECDSA)
	return address
}

// func TestHappyFlowMock(t *testing.T) {
// 	logger := logrus.NewEntry(logrus.New())

// 	logger.Infof("Starting intg test")

// 	srv1 := CreateTestOperator(t, 1)
// 	srv2 := CreateTestOperator(t, 2)
// 	srv3 := CreateTestOperator(t, 3)
// 	srv4 := CreateTestOperator(t, 4)

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
