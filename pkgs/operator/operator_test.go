package operator_test

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/consts"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/operator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/utils/test_utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

var (
	rootCert     = []string{"../../integration_test/certs/rootCA.crt"}
	operatorCert = "../../integration_test/certs/localhost.crt"
	operatorKey  = "../../integration_test/certs/localhost.key"
)

func TestRateLimit(t *testing.T) {
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	ops := wire.OperatorsCLI{}
	srv1 := test_utils.CreateTestOperatorFromFile(t, 1, "../../examples/operator1", version, operatorCert, operatorKey, stubClient)
	srv2 := test_utils.CreateTestOperatorFromFile(t, 2, "../../examples/operator2", version, operatorCert, operatorKey, stubClient)
	srv3 := test_utils.CreateTestOperatorFromFile(t, 3, "../../examples/operator3", version, operatorCert, operatorKey, stubClient)
	srv4 := test_utils.CreateTestOperatorFromFile(t, 4, "../../examples/operator4", version, operatorCert, operatorKey, stubClient)
	ops = append(
		ops,
		wire.OperatorCLI{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey},
		wire.OperatorCLI{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey},
		wire.OperatorCLI{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey},
		wire.OperatorCLI{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey},
	)
	// Initiator priv key
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	pubKey := priv.Public().(*rsa.PublicKey)
	initPubBytes, err := spec_crypto.EncodeRSAPublicKey(pubKey)
	require.NoError(t, err)
	t.Run("test /init rate limit", func(t *testing.T) {
		parts := make([]*spec.Operator, 0)
		for _, id := range []uint64{1, 2, 3, 4} {
			op := ops.ByID(id)
			pkBytes, err := spec_crypto.EncodeRSAPublicKey(op.PubKey)
			require.NoError(t, err)
			parts = append(parts, &spec.Operator{
				ID:     op.ID,
				PubKey: pkBytes,
			})
		}

		init := &spec.Init{
			Operators:             parts,
			T:                     3,
			WithdrawalCredentials: common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(),
			Fork:                  [4]byte{0, 0, 0, 0},
			Owner:                 common.HexToAddress("0x0000000000000000000000000000000000000007"),
			Nonce:                 0,
		}
		sszinit, err := init.MarshalSSZ()
		require.NoError(t, err)

		ts := &wire.Transport{
			Type:       wire.InitMessageType,
			Identifier: [24]byte{1, 1, 1, 1, 1},
			Data:       sszinit,
			Version:    []byte(version),
		}

		tsssz, err := ts.MarshalSSZ()
		require.NoError(t, err)

		sig, err := spec_crypto.SignRSA(priv, tsssz)
		require.NoError(t, err)

		signedTransportMsg := &wire.SignedTransport{
			Message:   ts,
			Signer:    initPubBytes,
			Signature: sig,
		}

		msg, err := signedTransportMsg.MarshalSSZ()
		require.NoError(t, err)

		client := req.C()
		client.SetRootCertsFromFile(rootCert...)
		r := client.R()

		r.SetBodyBytes(msg)

		// Send requests
		errChan := make(chan []byte)
		time.Sleep(time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer close(errChan)
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				res, err := r.Post(fmt.Sprintf("%v/%v", srv1.HttpSrv.URL, "init"))
				require.NoError(t, err)
				if res.Status == "429 Too Many Requests" {
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					errChan <- b
				}
			}
		}()
		for errResp := range errChan {
			require.NotEmpty(t, errResp)
			require.Equal(t, operator.ErrTooManyRouteRequests, string(errResp))
		}
		wg.Wait()
	})
	t.Run("test /dkg rate limit", func(t *testing.T) {
		client := req.C()
		client.SetRootCertsFromFile(rootCert...)
		r := client.R()
		exchMsg := wire.Exchange{
			PK:      []byte{},
			Commits: []byte{},
		}
		sszExch, err := exchMsg.MarshalSSZ()
		require.NoError(t, err)
		ts := &wire.Transport{
			Type:       wire.ExchangeMessageType,
			Identifier: [24]byte{1, 1, 1, 1, 1},
			Data:       sszExch,
			Version:    []byte(version),
		}
		tsssz, err := ts.MarshalSSZ()
		require.NoError(t, err)

		sig, err := spec_crypto.SignRSA(priv, tsssz)
		require.NoError(t, err)

		signedTransportMsg := &wire.SignedTransport{
			Message:   ts,
			Signer:    initPubBytes,
			Signature: sig,
		}
		signedTransportMsgEnc, err := signedTransportMsg.MarshalSSZ()
		require.NoError(t, err)
		var allMsgsBytes []byte
		allMsgsBytes = append(allMsgsBytes, signedTransportMsgEnc...)
		// sign message by initiator
		sigMultMsg, err := spec_crypto.SignRSA(priv, allMsgsBytes)
		require.NoError(t, err)
		multSignedTransport := &wire.MultipleSignedTransports{
			Identifier: [24]byte{1, 1, 1, 1, 1},
			Messages:   []*wire.SignedTransport{signedTransportMsg},
			Signature:  sigMultMsg,
		}
		msg, err := multSignedTransport.MarshalSSZ()
		require.NoError(t, err)

		r.SetBodyBytes(msg)

		// Send requests
		errChan := make(chan []byte)
		time.Sleep(time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer close(errChan)
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				res, err := r.Post(fmt.Sprintf("%v/%v", srv1.HttpSrv.URL, "dkg"))
				require.NoError(t, err)
				if res.Status == "429 Too Many Requests" {
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					errChan <- b
				}
			}
		}()
		for errResp := range errChan {
			require.NotEmpty(t, errResp)
			require.Equal(t, operator.ErrTooManyRouteRequests, string(errResp))
		}
		wg.Wait()
	})
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func TestWrongInitiatorSignature(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("operator-tests")
	ops := wire.OperatorsCLI{}
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	srv1 := test_utils.CreateTestOperatorFromFile(t, 1, "../../examples/operator1", version, operatorCert, operatorKey, stubClient)
	srv2 := test_utils.CreateTestOperatorFromFile(t, 2, "../../examples/operator2", version, operatorCert, operatorKey, stubClient)
	srv3 := test_utils.CreateTestOperatorFromFile(t, 3, "../../examples/operator3", version, operatorCert, operatorKey, stubClient)
	srv4 := test_utils.CreateTestOperatorFromFile(t, 4, "../../examples/operator4", version, operatorCert, operatorKey, stubClient)
	ops = append(
		ops,
		wire.OperatorCLI{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey},
		wire.OperatorCLI{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey},
		wire.OperatorCLI{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey},
		wire.OperatorCLI{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey},
	)
	t.Run("test wrong signature of init message", func(t *testing.T) {
		withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
		owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
		ids := []uint64{1, 2, 3, 4}

		c, err := initiator.New(ops, logger, version, rootCert)
		require.NoError(t, err)
		// compute threshold (3f+1)
		threshold := len(ids) - ((len(ids) - 1) / 3)
		parts := make([]*spec.Operator, 0)
		for _, id := range ids {
			op := c.Operators.ByID(id)
			require.NotNil(t, op)
			pkBytes, err := spec_crypto.EncodeRSAPublicKey(op.PubKey)
			require.NoError(t, err)
			parts = append(parts, &spec.Operator{
				ID:     op.ID,
				PubKey: pkBytes,
			})
		}
		wrongPub, err := spec_crypto.EncodeRSAPublicKey(&c.PrivateKey.PublicKey)
		require.NoError(t, err)
		encPub, err := spec_crypto.EncodeRSAPublicKey(&c.PrivateKey.PublicKey)
		require.NoError(t, err)
		c.Logger.Info("Initiator", zap.String("Pubkey:", fmt.Sprintf("%x", encPub)))
		// make init message
		init := &spec.Init{
			Operators:             parts,
			T:                     uint64(threshold),
			WithdrawalCredentials: withdraw.Bytes(),
			Fork:                  [4]byte{0, 0, 0, 0},
			Owner:                 owner,
			Nonce:                 0,
		}
		id := spec.NewID()
		sszinit, err := init.MarshalSSZ()
		require.NoError(t, err)
		initMessage := &wire.Transport{
			Type:       wire.InitMessageType,
			Identifier: id,
			Data:       sszinit,
			Version:    c.Version,
		}
		sig, err := hex.DecodeString("a32d0f695aad4a546b5507bb6b7cf43be7c54385589bbc6616bb97e58e839b596e8e827f8309488e6adc86562f7662738f46ae57f166e226913d66d6134149e8c6d6c60676da480c3ace2ea18f031ca4cfb51fa11a0595e63fe5808440b46c45d90e020f77bf35e64d7886ecf2e6f825168c955110753f73b37a5492191bd60a1bc7779f550b60aa37150ca2d16c15d33f014bca3dcfbb7a937312a51eb8d059a95203492e669238e5effdd38893b851d04f70cd58ad7ba0da7b21cb826b7397dbdffcbf6d66a8bcbf4e081a568c6e647e8d942c838533907ab7190c8a63eac73bec612cc1c44686164e734abec87ae223959b0f09f0c21cd99945e5319cb5a9")
		require.NoError(t, err)
		// Create signed init message
		signedInitMsg := &wire.SignedTransport{
			Message:   initMessage,
			Signer:    wrongPub,
			Signature: sig}
		signedInitMsgBts, err := signedInitMsg.MarshalSSZ()
		require.NoError(t, err)
		_, errs := c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, parts)
		require.Equal(t, 4, len(errs))
		for _, err := range errs {
			require.ErrorContains(t, err, "init: initiator signature isn't valid: crypto/rsa: verification error")
		}
	})
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

var testKeyshares = []byte(`{
	"version": "v1.1.0",
	"createdAt": "2023-12-05T06:41:55.291596636Z",
	"shares": [ 
		{
		"data": {
			"ownerNonce": 9,
			"ownerAddress ": "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494",
			"publicKey": "0xb53ca0ea01fb78ca1d00c1c7899f2d78cfbb83a34bc072359fa085b3dae05709e10c4a104d8b25b178d181073c9c33c9",
			"operators": [
				{
				"id": 1,
				"operatorKey": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"
				},
				{
				"id": 2,
				"operatorKey": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdnRVRWFlallqY3pBUWhnSTQ0S3cKcGZYZjhCNk1ZUjhOMzFmRVFLRGRDVmo5dUNPcHVybzYzSDdxWXNzMzVGaVdxNmRwMjR3M0dCRTAzR1llU1BSZgowTEVBVEJkYlhCVkY3WGR6ei9sV2UrblJNRG1Xdm1DTUZjRlRPRU5FYmhuTXVjOEQ1K3ZFTmo5cTQzbE4vejhqCmE2T2M4S2tEL2E4SW02Nm54ZkRhMjFyMzNaSW9GL1g5d0g2K25EN3Jockx5bzJub1lxaVJpT1NTTkp2R25UY08KazBmckk4b2xFNjR1clhxWXFLN2ZicXNaN082NnphN2ROTmc3MW1EWHlpdDlSTUlyR3lSME5xN0FUSkxwbytoTApEcldoY0h4M0NWb1dQZzNuR2phN0duVFhXU2FWb1JPSnBRVU9oYXgxNVJnZ2FBOHpodGgyOUorNnNNY2R6ZitQCkZ3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"
				},
				{
				"id": 3,
				"operatorKey": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdlFhZlo0ODJQYXRsYnRrOVdIb2MKZDBWdWNWWDk4QUlzenAvazlFTlYyQU82SVhQUXVqU1BtdUZrQTlibThsSllnWTJPb0lQU0RmK1JHWGNMc2R0VApzdEJhQ2JPL0pMOFlSejk4NURKejhBRlhDU0J3bW5mbzROSFptUjJGMVdMTE5CS2wzdVQ5Q1VLbC9RUnpKRFF1CjNNYVJ6eE5FVmdONWtvU1Nid0NxVDNDSCtjam5QU0pIeGhiaTNTaldOSnJFb3ZRUmN3ZUlpYXRrZEdVNWJOUkoKUW1LVldhYzhzVklYN2NDNE54V2RDNG1VM1RPK2Vlei90N2xVcnhSNjdnb21TbGdwaU5weFJ1M2dFajRkSWpINwpsZDlTYW1ObEJPeHV5N0lFMEJpdm5nSUdIKzVwcXZVTXhoM0N5WkVtMjFHd3JTRFhqcVpwWG92OEUwQkQ5eGY4ClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"
				},
				{
				"id": 4,
				"operatorKey": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBeFRWM2I5OHU4NmtzcEhQcWgrS2QKKzRHd0lSeEhwRHpEZjVlc3hjZytxaTlvbDRERmplUXMrbGloeUp5cGdOMXJwdTlQVnR5cXp2K3k5cEVNa0VXTgovYjBUQmdRMEp5TzdmNGliY1d5UUcrNGhVUS9XY3h1ZW5aUDA3S0VwTjh4Tk8xN3BzbmhRMXRqQVhybDNGN1lYCmlZdXl5Z0Rta2w0YjYrUDR6MjNhR01VSEtnTnJ5aFlZTFV4dWdycDVRTnJTV3lXNXFtb2EvYnJDenQ2RFJYb1UKU25JSkpSUVpPS2NnckdKMHVBYjJDRmtsL0xuaElxT2RZZ21aUG9oRmprVEorRnZNdkZsMjAwZ1BHbVpxUS9MMgpsM2ZBdmhZYlZRMlRVeUtmU2orYXZ1WUFZZnhKeG5OcWlmdkNkVGNmQzc3c0N0eFFERWVjY0pTVnVDbGZWeTFZCll3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"
				}
			]
			},
			"payload": {
			"publicKey": "0xb53ca0ea01fb78ca1d00c1c7899f2d78cfbb83a34bc072359fa085b3dae05709e10c4a104d8b25b178d181073c9c33c9",
			"operatorIds": [1, 2, 3, 4],
			"sharesData": "0x8b3d4bfb94ca3b9e7baa662c91df4d8590a94cd53d82cedcf850751abe8a0742c9f280ab6b0a7fdeeec2d0ea465991d903124f3c67c1efc8d55c14462c8cae197103f6d0675bff4ad50ea5c956cf25d4ca863c4a01ad062f92d2a9ca5bc6857dada7bfc2dc1f923da35ed019e7d93d49a9bbc6c36b7eb2f2ed22547f179681a89ea36efb81571998ffc7550581ec1a9fa2c98a4bb0d5586d2bdd88ae4fb64951628dd4103bd09decee3eb8a79f499d91d2e2b3b2d16d096951285f09e94542938f9b1e6384b09ab2cec5f1bf82655c0f62356f0de72e99cb4153c396941c4451d8cf2e2902954bef9e7f129428dc87b6968a6942feb4601dcf0d158b7de01e1f7d42b2da209f8c489fa967ed13124d29c2d01f6760920ac1f1df2f48d7f5022180783badbac329b25d710471dba61577b97d82b7d05068ae43f67e05677f14faf2d4a404277c93eb68ab208a8d34bc3b79680419cd7c2a15650aea8ea295f1071f6fa0910ba11603665bfd2869ea27cdce2416e716c7ab46f8d673fea0c1e4cd849556e1eaf27c540157e63e41003afa0429cedc53f96cee0a31e55324e190c5ddb901c1500f3dace6061d43a1cdf6c60a8ceed1e34ba7e04d5a984b04453a403ec6d5c8560dcdc741dfb1f6016083127a77d5d20251264143d954bfffefea0ac9667b91cb51f0ed6656180437ec7defee6a225e2be8cd2007bd342359ca0f3747925e6b6fd190a8157f69cd600610a0eda0b89834aafd6df687e88aa640507fb2e0e549ec7ff64d61fb884e13e38a67117552619989e84ea82e7dbc047ce50d171bd858f720449062863dfd07e6a0e605efb1d3d8913a98b076705eb1aabfcb71e12879ae4fe8718cf9d0a21d1f6c8851f84085cca0641b54d7090febf1a4e1a9541fffde62a6675496792fe418cb7955991d02a9c40fc3a530642eec4f4db674f2ed4199d07636dfc68bce794918f5e140286ecaebb6fcd305f837bfaf524dce15cc2e3e7f355c190c3a7ca23b7070f88ba6778cc3fbe1a5b11c9f2040bce8576afbfd827e79283db8e4fa7760eb8fa9c31821064a937d9748746ec3d67a363a8ffe30bb9b000ba2d7249c84bc2a897399a2f0ac5bc4b13259927dcce5dae97e3434cfb1e1f5464c1c1b2e9339ac4e7093d7222f0b2f8a610b34f43571a4f1bea3ebe6e801bb709f9e2e934091b366556b4d0dd528c97ad90e7fc5991adf403199c7a510055f2322d0bd948080425a98e380526cb59b541701535da273983415e49585efa9dfba04b2500ec637766b1293509e62ab6f6b74dacce09d91b9ff56a9d66cb687594feeca6b7867f0c3884612d19ed2d57409dd1b444ac4a20ea631dcf5b030ba7382c9e7d47b5d61525b892a3e38316495e2f7f6f219b5014cfe6bf3e8cdd183fbccdf9cce3277bb240b21775b55bea0246bb45e90e815a47d362e67319e34f8099ee711b4b9157e62cf7337f314c97d6fc2600fa981281bf5bb13ba4d223ae2c797b3f0b640d4be2b18f68a9229dd71f9db46affad7da03e0dc3749ed13470de19af108cfd4617383575e92f4240c1e6d92f681b292b7d1399238cc6b6c1c2ecf492b13c47f339fcbaf4fc19d4e2040a094e703841a94ad370ff864c68c8f40932daddaed4f36c49f373003859a03b2e493f8623a6d8e816180d4e9f781baabf3a4a77f660858ce0a5cc0213f7a9c95836369cff830768638ef20f2c3cba411c928d7a780797507d14b9a38f90f30c587e55ca3bfed42d424b2014b80074af41856b5f48bca24102ea2a079df097680fdcb77d9eef26f5c46373642513625ab4b2517b8ccbc49d8cda7fabb7427ffd077dbb015451b1502500d"
			}
  		}
  ]
  }`)

func TestRecoverSharesData(t *testing.T) {
	var ks *wire.KeySharesCLI
	var keys []*rsa.PrivateKey
	suite := kyber_bls12381.NewBLS12381Suite()
	err := json.Unmarshal(testKeyshares, &ks)
	require.NoError(t, err)

	opKey1, err := cli_utils.OpenPrivateKey("../../examples/operator1/password", "../../examples/operator1/encrypted_private_key.json")
	require.NoError(t, err)
	keys = append(keys, opKey1)
	opKey2, err := cli_utils.OpenPrivateKey("../../examples/operator2/password", "../../examples/operator2/encrypted_private_key.json")
	require.NoError(t, err)
	keys = append(keys, opKey2)
	opKey3, err := cli_utils.OpenPrivateKey("../../examples/operator3/password", "../../examples/operator3/encrypted_private_key.json")
	require.NoError(t, err)
	keys = append(keys, opKey3)
	opKey4, err := cli_utils.OpenPrivateKey("../../examples/operator4/password", "../../examples/operator4/encrypted_private_key.json")
	require.NoError(t, err)
	keys = append(keys, opKey4)

	sharesData, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
	require.NoError(t, err)

	operatorCount := len(keys)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		t.FailNow()
	}

	pubKeys := utils.SplitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := utils.SplitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	var kyberPrivShares []*share.PriShare
	var kyberPubShares []*share.PubShare
	for i, enck := range encryptedKeys {
		priv := keys[i]
		prShare, err := rsaencryption.DecodeKey(priv, enck)
		require.NoError(t, err)
		secret := &bls.SecretKey{}
		err = secret.SetHexString(string(prShare))
		require.NoError(t, err)
		// Find operator ID by PubKey
		var operatorID uint64
		for _, op := range ks.Shares[0].ShareData.Operators {
			b, err := spec_crypto.EncodeRSAPublicKey(&priv.PublicKey)
			require.NoError(t, err)
			if bytes.Equal(b, []byte(op.PubKey)) {
				operatorID = op.ID
			}
		}
		t.Log("Recovered operator ID", operatorID)
		v := suite.G1().Scalar().SetBytes(secret.Serialize())
		t.Logf("Recovered scalar %x", v)
		kyberPrivShare := &share.PriShare{
			I: int(i),
			V: v,
		}
		kyberPrivShares = append(kyberPrivShares, kyberPrivShare)
		kyberPubShare := &share.PubShare{
			I: int(i),
			V: suite.G1().Point().Mul(kyberPrivShare.V, nil),
		}
		kyberPubShares = append(kyberPubShares, kyberPubShare)
	}
	var kyberPubSharesFromPubs []*share.PubShare
	for i, pubk := range pubKeys {
		blsPub := &bls.PublicKey{}
		err := blsPub.Deserialize(pubk)
		require.NoError(t, err)
		v := suite.G1().Point()
		err = v.UnmarshalBinary(blsPub.Serialize())
		require.NoError(t, err)
		kyberPubShare := &share.PubShare{
			I: int(i),
			V: v,
		}
		kyberPubSharesFromPubs = append(kyberPubSharesFromPubs, kyberPubShare)
	}
	for i := 0; i < len(kyberPubSharesFromPubs); i++ {
		vFromPubs, err := kyberPubSharesFromPubs[i].V.MarshalBinary()
		require.NoError(t, err)
		v, err := kyberPubShares[i].V.MarshalBinary()
		require.NoError(t, err)
		require.Equal(t, v, vFromPubs)
		require.Equal(t, kyberPubSharesFromPubs[i].I, kyberPubShares[i].I)
	}
	secretPoly, err := share.RecoverPriPoly(suite.G1(), kyberPrivShares, 3, operatorCount)
	coefs := secretPoly.Coefficients()
	t.Logf("Ploly len %d", len(coefs))
	for _, c := range coefs {
		t.Logf("Ploly coef %s", c.String())
	}
	require.NoError(t, err)
	pubPoly := secretPoly.Commit(nil)
	pubShares := pubPoly.Shares(len(kyberPrivShares))
	recovered, err := share.RecoverCommit(suite.G1(), kyberPubSharesFromPubs, 3, operatorCount)
	if err != nil {
		t.Fatal(err)
	}
	if !recovered.Equal(pubPoly.Commit()) {
		t.Fatal("recovered commit does not match initial value")
	}
	polyRecovered, err := share.RecoverPubPoly(suite.G1(), pubShares, 3, operatorCount)
	if err != nil {
		t.Fatal(err)
	}
	require.True(t, pubPoly.Equal(polyRecovered))
	secret, err := share.RecoverSecret(suite.G1(), kyberPrivShares, 3, operatorCount)
	require.NoError(t, err)
	public := suite.G1().Point().Mul(secret, nil)

	pk := &bls.PublicKey{}
	err = pk.DeserializeHexStr(strings.Trim(ks.Shares[0].ShareData.PublicKey, "0x"))
	require.NoError(t, err)
	bytsPK, err := public.MarshalBinary()
	require.NoError(t, err)
	pkRecovered := &bls.PublicKey{}
	err = pkRecovered.Deserialize(bytsPK)
	require.NoError(t, err)
	require.True(t, pk.IsEqual(pkRecovered))

	_, commits := pubPoly.Info()
	exp := share.NewPubPoly(suite.G1(), suite.G1().Point().Base(), commits)
	for _, share := range kyberPrivShares {
		pubShare := exp.Eval(share.I)
		expShare := suite.G1().Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}
}
