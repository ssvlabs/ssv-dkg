package validator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func TestKeysharesJSON(t *testing.T) {
	tests := []struct {
		filename                string
		expectedValidatorPubKey string
		expectedOwnerAddress    string
		expectedNonce           uint64
		expectedErr             string
	}{
		{
			expectedValidatorPubKey: "b1b741af1f7f3064f13a860eafd644eba346b1852852a41fae6e229c18b04e76351be4d817788555153daa2b992acabc",
			expectedOwnerAddress:    "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494",
			expectedNonce:           100,
			filename:                "testdata/keyshares--valid.json",
			expectedErr:             "",
		},
		{
			filename:                "testdata/keyshares--duplicate-payload-operator.json",
			expectedValidatorPubKey: "b1b741af1f7f3064f13a860eafd644eba346b1852852a41fae6e229c18b04e76351be4d817788555153daa2b992acabc",
			expectedOwnerAddress:    "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494",
			expectedNonce:           100,
			expectedErr:             "operator id and payload operator ids are not equal",
		},
		{
			filename:                "testdata/keyshares--duplicate-data-operator.json",
			expectedValidatorPubKey: "b1b741af1f7f3064f13a860eafd644eba346b1852852a41fae6e229c18b04e76351be4d817788555153daa2b992acabc",
			expectedOwnerAddress:    "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494",
			expectedNonce:           100,
			expectedErr:             "operators not unique or not ordered",
		},
	}

	for _, test := range tests {
		name, ok := strings.CutSuffix(filepath.Base(test.filename), ".json")
		if !ok {
			t.Fatalf("invalid test filename: %s", test.filename)
		}
		t.Run(name, func(t *testing.T) {
			keyshares := &wire.KeySharesCLI{}
			keysharesData, err := os.ReadFile(test.filename)
			require.NoError(t, err)
			err = json.Unmarshal(keysharesData, keyshares)
			require.NoError(t, err)
			err = ValidateKeyshare(keyshares, test.expectedValidatorPubKey, test.expectedOwnerAddress, test.expectedNonce)
			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}

func TestDepositDataJSON(t *testing.T) {
	tests := []struct {
		filename                      string
		expectedWithdrawalCredentials common.Address
		expectedErr                   string
	}{
		{
			filename:                      "testdata/depositdata--valid.json",
			expectedWithdrawalCredentials: common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"),
			expectedErr:                   "",
		},
		{
			filename:                      "testdata/depositdata--invalid-pubkey.json",
			expectedWithdrawalCredentials: common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"),
			expectedErr:                   "err blsPublicKeyDeserialize",
		},
		{
			filename:                      "testdata/depositdata--invalid-signature.json",
			expectedWithdrawalCredentials: common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"),
			expectedErr:                   "err blsSignatureDeserialize",
		},
		{
			filename:                      "testdata/depositdata--invalid-fork.json",
			expectedWithdrawalCredentials: common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494"),
			expectedErr:                   "failed to get network by fork: unknown network",
		},
	}

	for _, test := range tests {
		name, ok := strings.CutSuffix(filepath.Base(test.filename), ".json")
		if !ok {
			t.Fatalf("invalid test filename: %s", test.filename)
		}
		t.Run(name, func(t *testing.T) {
			depositDataArray := make([]*wire.DepositDataCLI, 0)
			depositDataJson, err := os.ReadFile(test.filename)
			require.NoError(t, err)
			err = json.Unmarshal(depositDataJson, &depositDataArray)
			require.NoError(t, err)
			require.Equal(t, len(depositDataArray), 1)
			err = crypto.ValidateDepositDataCLI(depositDataArray[0], test.expectedWithdrawalCredentials)
			if test.expectedErr != "" {
				require.Error(t, err)
				require.Contains(t, err.Error(), test.expectedErr)
			} else {
				require.NoError(t, err)
			}
		})
	}
}
