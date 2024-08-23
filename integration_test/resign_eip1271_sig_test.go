package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
)

func TestResignValidEOASig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb2c0176e14077e792d3d2f72001687564a572f05d65d25bd6edb8777a68bf6981aa1769c68455d701825dcf1cc3a0453/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestResignInvalidEOASig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"

	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb2c0176e14077e792d3d2f72001687564a572f05d65d25bd6edb8777a68bf6981aa1769c68455d701825dcf1cc3a0453/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		_, _, _, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "mainnet", withdraw.Bytes(), [20]byte{}, 10)
		require.ErrorContains(t, err, "invalid signed signature")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestResignValidContractSig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			ret := make([]byte, 32) // needs to be 32 byte for packing
			copy(ret[:4], eip1271.MagicValue[:])

			return ret, nil
		},
		CodeAtMap: map[common.Address]bool{
			owner: true,
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb2c0176e14077e792d3d2f72001687564a572f05d65d25bd6edb8777a68bf6981aa1769c68455d701825dcf1cc3a0453/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "mainnet", withdraw.Bytes(), owner, 10)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestResignInvalidContractSig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			ret := make([]byte, 32) // needs to be 32 byte for packing
			copy(ret[:4], eip1271.InvalidSigValue[:])

			return ret, nil
		},
		CodeAtMap: map[common.Address]bool{
			owner: true,
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb2c0176e14077e792d3d2f72001687564a572f05d65d25bd6edb8777a68bf6981aa1769c68455d701825dcf1cc3a0453/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		_, _, _, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "holesky", withdraw.Bytes(), owner, 10)
		require.Error(t, err, "signature invalid")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
