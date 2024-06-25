package initiator_test

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils/test_utils"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
)

var (
	rootCert     = []string{"../../integration_test/certs/rootCA.crt"}
	operatorCert = "../../integration_test/certs/localhost.crt"
	operatorKey  = "../../integration_test/certs/localhost.key"
)

var jsonStr = []byte(`[
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
]`)

func TestStartDKG(t *testing.T) {
	err := logging.SetGlobalLogger("debug", "capital", "console", nil)
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
	withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
	owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
	t.Run("happy flow", func(t *testing.T) {
		intr, err := initiator.New(ops, logger, "test.version", rootCert)
		require.NoError(t, err)
		id := spec.NewID()
		depositData, keyshares, proofs, err := intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, keyshares, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test wrong amount of opeators < 4", func(t *testing.T) {
		intr, err := initiator.New(ops, logger, "test.version", rootCert)
		require.NoError(t, err)
		id := spec.NewID()
		_, _, _, err = intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
	})
	t.Run("test wrong amount of opeators > 13", func(t *testing.T) {
		intr, err := initiator.New(ops, logger, "test.version", rootCert)
		require.NoError(t, err)
		id := spec.NewID()
		_, _, _, err = intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, "prater", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: > 13")
	})
	t.Run("test opeators not unique", func(t *testing.T) {
		intr, err := initiator.New(ops, logger, "test.version", rootCert)
		require.NoError(t, err)
		id := spec.NewID()
		_, _, _, err = intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 7, 9, 10, 11, 12, 12}, "holesky", owner, 0)
		require.ErrorContains(t, err, "operator is not in given operator data list")
	})

	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func TestLoadOperators(t *testing.T) {
	t.Run("test load happy flow", func(t *testing.T) {
		var ops wire.OperatorsCLI
		err := json.Unmarshal(jsonStr, &ops)
		require.NoError(t, err)
		require.Len(t, ops, 4)
		require.Equal(t, ops[3].Addr, "http://localhost:3033", "addr not equal")
		key3, err := spec_crypto.ParseRSAPublicKey([]byte("LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdlFhZlo0ODJQYXRsYnRrOVdIb2MKZDBWdWNWWDk4QUlzenAvazlFTlYyQU82SVhQUXVqU1BtdUZrQTlibThsSllnWTJPb0lQU0RmK1JHWGNMc2R0VApzdEJhQ2JPL0pMOFlSejk4NURKejhBRlhDU0J3bW5mbzROSFptUjJGMVdMTE5CS2wzdVQ5Q1VLbC9RUnpKRFF1CjNNYVJ6eE5FVmdONWtvU1Nid0NxVDNDSCtjam5QU0pIeGhiaTNTaldOSnJFb3ZRUmN3ZUlpYXRrZEdVNWJOUkoKUW1LVldhYzhzVklYN2NDNE54V2RDNG1VM1RPK2Vlei90N2xVcnhSNjdnb21TbGdwaU5weFJ1M2dFajRkSWpINwpsZDlTYW1ObEJPeHV5N0lFMEJpdm5nSUdIKzVwcXZVTXhoM0N5WkVtMjFHd3JTRFhqcVpwWG92OEUwQkQ5eGY4ClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"))
		require.NoError(t, err)
		require.True(t, ops[2].PubKey.Equal(key3), "pubkey not equal")
	})
	t.Run("test wrong pub key encoding", func(t *testing.T) {
		var ops wire.OperatorsCLI
		err := json.Unmarshal([]byte(`[
      {
        "id": 1,
        "public_key": "LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
        "ip": "http://localhost:3030"
      }
    ]`), &ops)
		require.ErrorContains(t, err, "decode PEM block")
	})
	t.Run("test wrong operator URL", func(t *testing.T) {
		var ops wire.OperatorsCLI
		err := json.Unmarshal([]byte(`[
      {
        "id": 1,
        "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
        "ip": "wrongURL"
      }
    ]`), &ops)
		require.ErrorContains(t, err, "invalid operator URL")
	})
}

func generateOperators(ids []uint64) wire.OperatorsCLI {
	m := make([]wire.OperatorCLI, 0, len(ids))
	for _, i := range ids {
		m = append(m, wire.OperatorCLI{
			Addr: "",
			ID:   i,
			PubKey: &rsa.PublicKey{
				N: big.NewInt(1),
				E: 0,
			},
		})
	}
	return m
}

func TestValidateDKGParams(t *testing.T) {

	ops_1_13 := generateOperators([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})
	ops_not_serial := generateOperators([]uint64{1, 15, 3, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13})

	tests := []struct {
		name    string
		ids     []uint64
		ops     wire.OperatorsCLI
		wantErr bool
		errMsg  string
	}{
		{
			name:    "less than 4 operators",
			ids:     []uint64{1, 2, 3},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "wrong operators len: < 4",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13: got [1 2 3 4 5]",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13: got [1 2 3 4 5 6 7 8]",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13: got [1 2 3 4 5 6 7 8 9]",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13: got [1 2 3 4 5 6 7 8 9 10 11]",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13: got [1 2 3 4 5 7 8 9 10 11 12]",
		},
		{
			name:    "more than 13 operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "wrong operators len: > 13",
		},
		{
			name:    "duplicate operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 12},
			ops:     ops_1_13,
			wantErr: true,
			errMsg:  "operators ids should be unique in the list",
		},
		{
			name:    "4 valid operators",
			ids:     []uint64{1, 2, 3, 4},
			ops:     ops_1_13,
			wantErr: false,
		},
		{
			name:    "7 valid operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7},
			ops:     ops_1_13,
			wantErr: false,
		},
		{
			name:    "10 valid operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10},
			ops:     ops_1_13,
			wantErr: false,
		},
		{
			name:    "13 valid operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
			ops:     ops_1_13,
			wantErr: false,
		},
		{
			name:    "other valid operators",
			ids:     []uint64{1, 15, 3, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13},
			ops:     ops_not_serial,
			wantErr: false,
		},
		{
			name:    "op not in list",
			ids:     []uint64{1, 15, 21, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13},
			ops:     ops_not_serial,
			wantErr: true,
			errMsg:  "operator is not in given operator data list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := initiator.ValidatedOperatorData(tt.ids, tt.ops)
			switch {
			case tt.wantErr:
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q but got %q", tt.errMsg, err.Error())
				}
			case err != nil:
				t.Errorf("unexpected error: %v", err)
			default:
				// verify list is ok
				need := len(tt.ids)
				for _, id := range tt.ids {
					for _, op := range res {
						if op.ID == id {
							need--
							break
						}
					}
				}

				require.Equal(t, need, 0)
			}
		})
	}
}

func TestRemoveTrailSlash(t *testing.T) {
	var jsonStr = []byte(`[
	{
		"id": 1,
		"public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
		"ip": "http://localhost:3030"
	},
	{
		"id": 2,
		"public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdnRVRWFlallqY3pBUWhnSTQ0S3cKcGZYZjhCNk1ZUjhOMzFmRVFLRGRDVmo5dUNPcHVybzYzSDdxWXNzMzVGaVdxNmRwMjR3M0dCRTAzR1llU1BSZgowTEVBVEJkYlhCVkY3WGR6ei9sV2UrblJNRG1Xdm1DTUZjRlRPRU5FYmhuTXVjOEQ1K3ZFTmo5cTQzbE4vejhqCmE2T2M4S2tEL2E4SW02Nm54ZkRhMjFyMzNaSW9GL1g5d0g2K25EN3Jockx5bzJub1lxaVJpT1NTTkp2R25UY08KazBmckk4b2xFNjR1clhxWXFLN2ZicXNaN082NnphN2ROTmc3MW1EWHlpdDlSTUlyR3lSME5xN0FUSkxwbytoTApEcldoY0h4M0NWb1dQZzNuR2phN0duVFhXU2FWb1JPSnBRVU9oYXgxNVJnZ2FBOHpodGgyOUorNnNNY2R6ZitQCkZ3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
		"ip": "http://localhost:3031/"
	}
	]`)

	var ops wire.OperatorsCLI
	err := json.Unmarshal(jsonStr, &ops)

	require.Nil(t, err)
	require.Equal(t, "http://localhost:3030", ops[0].Addr)
	require.Equal(t, "http://localhost:3031", ops[1].Addr)
}

func TestDepositDataSigningAndVerification(t *testing.T) {
	tests := []struct {
		network                       core.Network
		testname                      string
		validatorPubKey               []byte
		validatorPrivKey              []byte
		withdrawalPubKey              []byte
		expectedWithdrawalCredentials []byte
		expectedSig                   []byte
		expectedRoot                  []byte
		expectedErr                   error
	}{
		{
			testname:                      "valid mainnet deposit",
			network:                       core.MainNetwork,
			validatorPubKey:               must(hex.DecodeString("b3d50de8d77299da8d830de1edfb34d3ce03c1941846e73870bb33f6de7b8a01383f6b32f55a1d038a4ddcb21a765194")),
			validatorPrivKey:              must(hex.DecodeString("175db1c5411459893301c3f2ebe740e5da07db8f17c2df4fa0be6d31a48a4f79")),
			withdrawalPubKey:              must(hex.DecodeString("8d176708b908f288cc0e9d43f75674e73c0db94026822c5ce2c3e0f9e773c9ee95fdba824302f1208c225b0ed2d54154")),
			expectedWithdrawalCredentials: must(hex.DecodeString("005b55a6c968852666b132a80f53712e5097b0fca86301a16992e695a8e86f16")),
			expectedSig:                   must(hex.DecodeString("8ab63bb2ef45d5fe4b5ba3b6aa2db122db350c05846b6ffc1415c603ba998226599a21aa65a8cb55c1b888767bdac2b51901d34cde41003c689b8c125fc67d3abd2527ccaf1390c13c3fc65a7422de8a7e29ae8e9736321606172c7b3bf6de36")),
			expectedRoot:                  must(hex.DecodeString("76139d2c8d8e87a4737ce7acbf97ce8980732921550c5443a8754635c11296d3")),
			expectedErr:                   nil,
		},
		{
			testname:                      "invalid mainnet deposit",
			network:                       core.MainNetwork,
			validatorPubKey:               must(hex.DecodeString("b3d50de8d77299da8d830de1edfb34d3ce03c1941846e73870bb33f6de7b8a01383f6b32f55a1d038a4ddcb21a765194")),
			validatorPrivKey:              must(hex.DecodeString("165db1c5411459893301c3f2ebe740e5da07db8f17c2df4fa0be6d31a48a4f79")),
			withdrawalPubKey:              must(hex.DecodeString("8d176708b908f288cc0e9d43f75674e73c0db94026822c5ce2c3e0f9e773c9ee95fdba824302f1208c225b0ed2d54154")),
			expectedWithdrawalCredentials: must(hex.DecodeString("005b55a6c968852666b132a80f53712e5097b0fca86301a16992e695a8e86f16")),
			expectedSig:                   must(hex.DecodeString("a88d0fd588836c5756ec7f2fe2bc8b6fc5723d018c8d31c8f42b239ac6cf7c2f9ae129caafaebb5f2f25e7821678b41819bc24f6eeebe0d8196cea13581f72ac501f3e7e9e4bc596e6a545ac109fb2ff1d7eb03923454dc5258718b43427a757")),
			expectedRoot:                  must(hex.DecodeString("76139d2c8d8e87a4737ce7acbf97ce8980732921550c5443a8754635c11296d3")),
			expectedErr:                   errors.New("failed to verify deposit roots: failed to verify deposit data: invalid signature"),
		},
		{
			testname:                      "valid prater deposit",
			network:                       core.PraterNetwork,
			validatorPubKey:               must(hex.DecodeString("b3d50de8d77299da8d830de1edfb34d3ce03c1941846e73870bb33f6de7b8a01383f6b32f55a1d038a4ddcb21a765194")),
			validatorPrivKey:              must(hex.DecodeString("175db1c5411459893301c3f2ebe740e5da07db8f17c2df4fa0be6d31a48a4f79")),
			withdrawalPubKey:              must(hex.DecodeString("8d176708b908f288cc0e9d43f75674e73c0db94026822c5ce2c3e0f9e773c9ee95fdba824302f1208c225b0ed2d54154")),
			expectedWithdrawalCredentials: must(hex.DecodeString("005b55a6c968852666b132a80f53712e5097b0fca86301a16992e695a8e86f16")),
			expectedSig:                   must(hex.DecodeString("a88d0fd588836c5756ec7f2fe2bc8b6fc5723d018c8d31c8f42b239ac6cf7c2f9ae129caafaebb5f2f25e7821678b41819bc24f6eeebe0d8196cea13581f72ac501f3e7e9e4bc596e6a545ac109fb2ff1d7eb03923454dc5258718b43427a757")),
			expectedRoot:                  must(hex.DecodeString("aa940a26af67a676bcd807b0fd3f39aadbfc6862e380e115051683e1fccc0171")),
			expectedErr:                   nil,
		},
	}

	require.NoError(t, core.InitBLS())

	for _, test := range tests {
		t.Run(test.testname, func(t *testing.T) {
			sk := &bls.SecretKey{}
			err := sk.SetHexString(hex.EncodeToString(test.validatorPrivKey))
			require.NoError(t, err)

			// create data
			depositData, err := crypto.SignDepositMessage(
				test.network,
				sk,
				&phase0.DepositMessage{
					PublicKey:             phase0.BLSPubKey(test.validatorPubKey),
					WithdrawalCredentials: crypto.BLSWithdrawalCredentials(test.withdrawalPubKey),
					Amount:                spec_crypto.MaxEffectiveBalanceInGwei,
				},
			)
			require.NoError(t, err)

			depositDataCLI, err := crypto.BuildDepositDataCLI(test.network, depositData, wire.DepositCliVersion)
			require.NoError(t, err)
			err = crypto.ValidateDepositDataCLIBLS(depositDataCLI, test.withdrawalPubKey)
			if test.expectedErr != nil {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr.Error())
				return
			}
			require.NoError(t, err)

			require.Equal(t, sk.GetPublicKey().SerializeToHexStr(), depositDataCLI.PubKey, "0x")
			require.Equal(t, test.expectedWithdrawalCredentials, depositData.WithdrawalCredentials)
			require.Equal(t, spec_crypto.MaxEffectiveBalanceInGwei, depositData.Amount)
			require.Equal(t, hex.EncodeToString(test.expectedRoot), depositDataCLI.DepositDataRoot)
			require.Equal(t, hex.EncodeToString(test.expectedSig), depositDataCLI.Signature, "0x")
		})
	}
}

func must[T any](v T, err error) T {
	if err != nil {
		panic(err)
	}
	return v
}
