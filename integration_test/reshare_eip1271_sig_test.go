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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestReshareValidEOASig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("../examples/initiator/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("../examples/initiator/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
	require.NoError(t, err)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		newId := spec.NewID()
		rMsg, err := clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", withdraw[:], owner, 0, signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ReshareMessage{rMsg}
		signedReshare, err := clnt.SignReshare(rMsgs, sk.PrivateKey)
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResharing(newId, signedReshare)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareInvalidEOASig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"

	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
	require.NoError(t, err)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		_, err := clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", withdraw[:], [20]byte{0}, 0, signedProofs[0])
		require.Error(t, err, "invalid owner address")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareValidContractSig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("../examples/initiator/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("../examples/initiator/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
	require.NoError(t, err)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			ret := make([]byte, 32) // needs to be 32 byte for packing
			copy(ret[:4], eip1271.MAGIC_VALUE[:])

			return ret, nil
		},
		CodeAtMap: map[common.Address]bool{
			owner: true,
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		newId := spec.NewID()
		rMsg, err := clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", withdraw[:], owner, 0, signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ReshareMessage{rMsg}
		signedReshare, err := clnt.SignReshare(rMsgs, sk.PrivateKey)
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResharing(newId, signedReshare)
		require.NoError(t, err)
		err = validator.ValidateResults(depositData, ks[0], proofs, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareInvalidContractSig(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	withdraw := common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494")
	// Open ethereum keystore
	jsonBytes, err := os.ReadFile("../examples/initiator/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
	require.NoError(t, err)
	keyStorePassword, err := os.ReadFile(filepath.Clean("../examples/initiator/password"))
	require.NoError(t, err)
	sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PrivateKey.PublicKey)
	signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xaa57eab07f1a740672d0c106867d366c798d3b932d373c88cf047da1a3c16d0816ac58bab5a9d6f6f4b63a07608f8f39/proofs.json")
	require.NoError(t, err)
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
	t.Run("test reshare 4 new operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		newId := spec.NewID()
		rMsg, err := clnt.ConstructReshareMessage(ids, newIds, signedProofs[0][0].Proof.ValidatorPubKey, "holesky", withdraw[:], owner, 0, signedProofs[0])
		require.NoError(t, err)
		rMsgs := []*wire.ReshareMessage{rMsg}
		signedReshare, err := clnt.SignReshare(rMsgs, sk.PrivateKey)
		require.NoError(t, err)
		_, _, _, err = clnt.StartResharing(newId, signedReshare)
		require.Error(t, err, "signature invalid")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
