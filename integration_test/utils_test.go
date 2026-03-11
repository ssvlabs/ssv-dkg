package integration_test

import (
	"crypto/ecdsa"
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils/test_utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

const testVersion = "test.version"

// dynamicTestEnv holds shared state for tests that create operators with random keys.
type dynamicTestEnv struct {
	logger  *zap.Logger
	servers []*test_utils.TestOperator
	ops     wire.OperatorsCLI
}

// setupDynamicTest creates operators with random keys and registers cleanup.
func setupDynamicTest(t *testing.T) *dynamicTestEnv {
	t.Helper()
	logger := zap.L().Named("integration-tests")
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperators(t, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	return &dynamicTestEnv{
		logger:  logger,
		servers: servers,
		ops:     ops,
	}
}

// fixtureTestEnv holds shared state for tests that use pre-existing operator keys from the examples folder.
type fixtureTestEnv struct {
	logger   *zap.Logger
	withdraw common.Address
	owner    common.Address
	sk       *ecdsa.PrivateKey
	servers  []*test_utils.TestOperator
	ops      wire.OperatorsCLI
}

// setupFixtureTest creates operators from the examples folder and loads the test keystore.
func setupFixtureTest(t *testing.T) *fixtureTestEnv {
	t.Helper()
	logger := zap.L().Named("integration-tests")
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
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
	servers, ops := createOperatorsFromExamplesFolder(t, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	return &fixtureTestEnv{
		logger:   logger,
		withdraw: withdraw,
		owner:    owner,
		sk:       sk.PrivateKey,
		servers:  servers,
		ops:      ops,
	}
}

// loadCeremonyProofs loads proofs from a fixture directory, handling the single-validator nested directory structure.
func loadCeremonyProofs(t *testing.T, baseDir, ceremonyName string, valCount int) [][]*spec.SignedProof {
	t.Helper()
	proofsFilePath := baseDir + "/" + ceremonyName + "/proofs.json"
	if valCount == 1 {
		ceremonyDir, err := os.ReadDir(baseDir + "/" + ceremonyName)
		require.NoError(t, err)
		proofsFilePath = baseDir + "/" + ceremonyName + "/" + ceremonyDir[0].Name() + "/proofs.json"
	}
	signedProofs, err := wire.LoadProofs(proofsFilePath)
	require.NoError(t, err)
	return signedProofs
}

// signMessages signs any ceremony message (reshare or resign) and returns raw signature bytes.
func signMessages(t *testing.T, msg interface{}, sk *ecdsa.PrivateKey) []byte {
	t.Helper()
	hash, err := utils.GetMessageHash(msg)
	require.NoError(t, err)
	sig, err := eth_crypto.Sign(hash[:], sk)
	require.NoError(t, err)
	return sig
}

// executeReshare signs reshare messages and executes the resharing ceremony.
func executeReshare(t *testing.T, clnt *initiator.Initiator, rMsgs []*wire.ReshareMessage, sk *ecdsa.PrivateKey) ([]*wire.DepositDataCLI, []*wire.KeySharesCLI, [][]*wire.SignedProof, error) {
	t.Helper()
	signedReshare := wire.SignedReshare{Messages: rMsgs, Signature: signMessages(t, rMsgs, sk)}
	return clnt.StartResharing(spec.NewID(), &signedReshare)
}

// executeResign signs resign messages and executes the resigning ceremony.
func executeResign(t *testing.T, clnt *initiator.Initiator, rMsgs []*wire.ResignMessage, sk *ecdsa.PrivateKey) ([]*wire.DepositDataCLI, []*wire.KeySharesCLI, [][]*wire.SignedProof, error) {
	t.Helper()
	signedResign := wire.SignedResign{Messages: rMsgs, Signature: signMessages(t, rMsgs, sk)}
	return clnt.StartResigning(spec.NewID(), &signedResign)
}

// eip1271TestEnv holds shared state for EIP-1271 signature tests.
type eip1271TestEnv struct {
	withdraw common.Address
	owner    common.Address
	sk       *ecdsa.PrivateKey
	clnt     *initiator.Initiator
	ops      wire.OperatorsCLI
}

// setupEIP1271Test loads a keystore, creates operators with owner-dependent stubs, and returns a ready-to-use test environment.
func setupEIP1271Test(t *testing.T, keystoreDir string, makeClient func(owner common.Address) *stubs.Client) *eip1271TestEnv {
	t.Helper()
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	jsonBytes, err := os.ReadFile(filepath.Clean(keystoreDir + "/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")) //nolint:gosec // test-only path from trusted caller
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean(keystoreDir + "/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	stubClient := makeClient(owner)
	servers, ops := createOperatorsFromExamplesFolder(t, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	clnt, err := initiator.New(ops, zap.L().Named("integration-tests"), testVersion, rootCert, false)
	require.NoError(t, err)
	return &eip1271TestEnv{withdraw: withdraw, owner: owner, sk: sk.PrivateKey, clnt: clnt, ops: ops}
}
