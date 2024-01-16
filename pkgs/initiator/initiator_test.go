package initiator_test

import (
	"crypto/rsa"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils/test_utils"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
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

const examplePath = "../../examples/"

func TestStartDKG(t *testing.T) {
	err := logging.SetGlobalLogger("debug", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("operator-tests")
	ops := make(map[uint64]initiator.Operator)
	version := "v1.0.2"
	srv1 := test_utils.CreateTestOperatorFromFile(t, 1, examplePath, version)
	srv2 := test_utils.CreateTestOperatorFromFile(t, 2, examplePath, version)
	srv3 := test_utils.CreateTestOperatorFromFile(t, 3, examplePath, version)
	srv4 := test_utils.CreateTestOperatorFromFile(t, 4, examplePath, version)
	ops[1] = initiator.Operator{srv1.HttpSrv.URL, 1, &srv1.PrivKey.PublicKey}
	ops[2] = initiator.Operator{srv2.HttpSrv.URL, 2, &srv2.PrivKey.PublicKey}
	ops[3] = initiator.Operator{srv3.HttpSrv.URL, 3, &srv3.PrivKey.PublicKey}
	ops[4] = initiator.Operator{srv4.HttpSrv.URL, 4, &srv4.PrivKey.PublicKey}
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
	owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
	t.Run("happy flow", func(t *testing.T) {
		intr := initiator.New(priv, ops, logger, "v1.0.2")
		id := crypto.NewID()
		depositData, keyshares, _, err := intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = test_utils.VerifySharesData([]uint64{1, 2, 3, 4}, []*rsa.PrivateKey{srv1.PrivKey, srv2.PrivKey, srv3.PrivKey, srv4.PrivKey}, keyshares, owner, 0)
		require.NoError(t, err)
		err = initiator.VerifyDepositData(depositData, withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
	})
	t.Run("test wrong amount of opeators < 4", func(t *testing.T) {
		intr := initiator.New(priv, ops, logger, "v1.0.2")
		id := crypto.NewID()
		_, _, _, err = intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
	})
	t.Run("test wrong amount of opeators > 13", func(t *testing.T) {
		intr := initiator.New(priv, ops, logger, "v1.0.2")
		id := crypto.NewID()
		_, _, _, err = intr.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, "prater", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: > 13")
	})
	t.Run("test opeators not unique", func(t *testing.T) {
		intr := initiator.New(priv, ops, logger, "v1.0.2")
		id := crypto.NewID()
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
		ops, err := initiator.LoadOperatorsJson(jsonStr)
		require.NoError(t, err)
		require.Len(t, ops, 4)
		require.Equal(t, ops[4].Addr, "http://localhost:3033", "addr not equal")
		key3, err := crypto.ParseRSAPubkey([]byte("LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdlFhZlo0ODJQYXRsYnRrOVdIb2MKZDBWdWNWWDk4QUlzenAvazlFTlYyQU82SVhQUXVqU1BtdUZrQTlibThsSllnWTJPb0lQU0RmK1JHWGNMc2R0VApzdEJhQ2JPL0pMOFlSejk4NURKejhBRlhDU0J3bW5mbzROSFptUjJGMVdMTE5CS2wzdVQ5Q1VLbC9RUnpKRFF1CjNNYVJ6eE5FVmdONWtvU1Nid0NxVDNDSCtjam5QU0pIeGhiaTNTaldOSnJFb3ZRUmN3ZUlpYXRrZEdVNWJOUkoKUW1LVldhYzhzVklYN2NDNE54V2RDNG1VM1RPK2Vlei90N2xVcnhSNjdnb21TbGdwaU5weFJ1M2dFajRkSWpINwpsZDlTYW1ObEJPeHV5N0lFMEJpdm5nSUdIKzVwcXZVTXhoM0N5WkVtMjFHd3JTRFhqcVpwWG92OEUwQkQ5eGY4ClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K"))
		require.NoError(t, err)
		require.True(t, ops[3].PubKey.Equal(key3), "pubkey not equal")
	})
	t.Run("test wrong pub key encoding", func(t *testing.T) {
		_, err := initiator.LoadOperatorsJson([]byte(`[
      {
        "id": 1,
        "public_key": "LS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
        "ip": "http://localhost:3030"
      }
    ]`))
		require.ErrorContains(t, err, "decode PEM block")
	})
	t.Run("test wrong operator URL", func(t *testing.T) {
		_, err := initiator.LoadOperatorsJson([]byte(`[
      {
        "id": 1,
        "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanAKQThDMWNYZ3VseHkyK0tDNldpWGo3NThuMjl4b1NsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMgpQRW1UZFcxcGp5TmV1N2RDUWtGTHF3b3JGZ1AzVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3CnUrY3hvZFJ4d01RZHZiN29mT0FhbVhxR1haZ0NhNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWEKd1J1SFRTTlNZcEdmbi9ud0FROHVDaW55SnNQV0Q0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISAp5V25ORjZTS2tRalI2MDJwQ3RXTkZRMi9wUVFqblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFClN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
        "ip": "wrongURL"
      }
    ]`))
		require.ErrorContains(t, err, "invalid operator URL")
	})
}

func generateOperators(ids []uint64) initiator.Operators {
	m := make(map[uint64]initiator.Operator)
	for _, i := range ids {
		m[i] = initiator.Operator{
			Addr: "",
			ID:   i,
			PubKey: &rsa.PublicKey{
				N: big.NewInt(1),
				E: 0,
			},
		}
	}

	return m
}

func TestValidateDKGParams(t *testing.T) {

	ops_1_13 := generateOperators([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})
	ops_not_serial := generateOperators([]uint64{1, 15, 3, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13})

	tests := []struct {
		name    string
		ids     []uint64
		ops     initiator.Operators
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
			errMsg:  "amount of operators should be 4,7,10,13",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13",
		},
		{
			name:    "not valid number of operators",
			ids:     []uint64{1, 2, 3, 4, 5, 7, 8, 9, 10, 11, 12},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "amount of operators should be 4,7,10,13",
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

	ops, err := initiator.LoadOperatorsJson(jsonStr)

	require.Nil(t, err)
	require.Equal(t, "http://localhost:3030", ops[1].Addr)
	require.Equal(t, "http://localhost:3031", ops[2].Addr)
}
