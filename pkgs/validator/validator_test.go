package validator

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/stretchr/testify/require"
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
			filename:                "testdata/valid-keyshares.json",
			expectedErr:             "",
		},
		{
			filename:                "testdata/invalid-keyshares--duplicate-payload-operator.json",
			expectedValidatorPubKey: "b1b741af1f7f3064f13a860eafd644eba346b1852852a41fae6e229c18b04e76351be4d817788555153daa2b992acabc",
			expectedOwnerAddress:    "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494",
			expectedNonce:           100,
			expectedErr:             "operators and not unique and ordered",
		},
		{
			filename:                "testdata/invalid-keyshares--duplicate-data-operator.json",
			expectedValidatorPubKey: "b1b741af1f7f3064f13a860eafd644eba346b1852852a41fae6e229c18b04e76351be4d817788555153daa2b992acabc",
			expectedOwnerAddress:    "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494",
			expectedNonce:           100,
			expectedErr:             "operators and not unique and ordered",
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
