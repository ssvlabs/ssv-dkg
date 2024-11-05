package integration_test

import (
	"encoding/hex"
	"os"
	"path/filepath"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
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
	clnt, err := initiator.New(ops, logger, version, rootCert, false)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk.PrivateKey)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		depositData, ks, proofs, err := clnt.StartResigning(id, &signedResign)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, owner, 10, withdraw)
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
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	c, err := initiator.New(ops, logger, version, rootCert, false)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		ops, err := initiator.ValidatedOperatorData(ids, c.Operators)
		require.NoError(t, err)
		// validate proofs
		for i, op := range ops {
			if err := spec.ValidateCeremonyProof(owner, signedProofs[0][0].Proof.ValidatorPubKey, op, *signedProofs[0][i]); err != nil {
				require.NoError(t, err)
			}
		}
		// Construct resign message
		_, err = c.ConstructResignMessage(
			ids,
			signedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			[20]byte{},
			uint64(nonce),
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.ErrorContains(t, err, "invalid owner address")
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
			copy(ret[:4], eip1271.MAGIC_VALUE_ETH_SIGN[:])

			return ret, nil
		},
		CodeAtMap: map[common.Address]bool{
			owner: true,
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert, false)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0][0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk.PrivateKey)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		depositData, ks, proofs, err := clnt.StartResigning(id, &signedResign)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, owner, 10, withdraw)
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
	clnt, err := initiator.New(ops, logger, version, rootCert, false)
	require.NoError(t, err)
	t.Run("test resign 4 operators", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
		require.NoError(t, err)
		// re-sign
		id := spec.NewID()
		rMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			signedProofs[0][0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
			signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ResignMessage{rMsg}
		siganture, err := SignResign(rMsgs, sk.PrivateKey)
		require.NoError(t, err)
		signatureBytes, err := hex.DecodeString(siganture)
		require.NoError(t, err)
		signedResign := wire.SignedResign{Messages: rMsgs, Signature: signatureBytes}
		_, _, _, err = clnt.StartResigning(id, &signedResign)
		require.Error(t, err, "signature invalid")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
