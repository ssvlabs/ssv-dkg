package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
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
	amount := spec_crypto.MIN_ACTIVATION_BALANCE
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "mainnet", withdraw.Bytes(), owner, 10, uint64(amount))
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
	ids := []uint64{11, 22, 33, 44}
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	owner := common.HexToAddress("0xdcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	nonce := 0
	amount := spec_crypto.MIN_ACTIVATION_BALANCE
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
	c, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
		require.NoError(t, err)
		id := spec.NewID()
		ops, err := initiator.ValidatedOperatorData(ids, c.Operators)
		require.NoError(t, err)
		// validate proofs
		for i, op := range ops {
			if err := spec.ValidateCeremonyProof(owner, signedProofs[0][0].Proof.ValidatorPubKey, op, *signedProofs[0][i]); err != nil {
				require.NoError(t, err)
			}
		}
		// Construct resign message
		rMsg, err := c.ConstructResignMessage(
			ids,
			signedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			[20]byte{},
			uint64(nonce),
			uint64(amount),
			sk.PrivateKey,
			signedProofs[0])
		require.NoError(t, err)
		_, err = c.ResignMessageFlowHandling(
			rMsg,
			id,
			rMsg.Operators)
		require.ErrorContains(t, err, "signature invalid") // spec
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
	amount := spec_crypto.MIN_ACTIVATION_BALANCE
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
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "mainnet", withdraw.Bytes(), owner, 10, uint64(amount))
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
	amount := spec_crypto.MIN_ACTIVATION_BALANCE
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
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		require.NoError(t, err)
		_, _, _, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44}, signedProofs[0], sk.PrivateKey, "holesky", withdraw.Bytes(), owner, 10, uint64(amount))
		require.Error(t, err, "signature invalid")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
