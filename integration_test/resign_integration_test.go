package integration_test

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
)

func TestResignHappyFlows(t *testing.T) {
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
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test 4 operators resign happy flow", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb92b076fdd7dcfb209bec593abb1291ee9ddfe8ecab279dc851b06bcd3fb056872888f947e4b5f9d6df6703e547679e7/proofs.json")
		require.NoError(t, err)
		proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
		// re-sign
		id := spec.NewID()
		// Construct resign message
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk.PrivateKey,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 7 operators resign happy flow", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/7/000001-0xb4d29a4e25f152f77f76d5797b0dea319b03accee76565498d8b815a37c4db4d186c9e165f3e7eef9cebd503fd80d1ef/proofs.json")
		require.NoError(t, err)
		proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
		// re-sign
		id := spec.NewID()
		// Construct resign message
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk.PrivateKey,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 10 operators resign happy flow", func(t *testing.T) {
		signedProofs, err := wire.LoadProofs("./stubs/10/000001-0xb636059de70f3f09303b5a0cb19d34eea4f316b27312fb525ea0e6b2a281c466a3fa32bfc3e6f5163bfe6a97cac9f651/proofs.json")
		require.NoError(t, err)
		proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
		// re-sign
		id := spec.NewID()
		// Construct resign message
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk.PrivateKey,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err := clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	// t.Run("test 13 operators resign happy flow", func(t *testing.T) {
	// 	signedProofs, err := wire.LoadProofs("./stubs/13/000001-0x80ed3a2cfd4260551049976dcfa2109bf9a6b3c909f0f3a811eed2c779e8415c664103387b934ac43d91f1e703dcbd4a/proofs.json")
	// 	require.NoError(t, err)
	// 	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	// 	// re-sign
	// 	id := spec.NewID()
	// 	// Construct resign message
	// 	reshareMsg, err := clnt.ConstructResignMessage(
	// 		[]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113},
	// 		proofsData[0].Proof.ValidatorPubKey,
	// 		"holesky",
	// 		withdraw.Bytes(),
	// 		owner,
	// 		2,
	// 		sk.PrivateKey,
	// 		proofsData)
	// 	require.NoError(t, err)
	// 	depositData, ks, proofs, err := clnt.StartResigning(id, reshareMsg)
	// 	require.NoError(t, err)
	// 	err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 2, withdraw)
	// 	require.NoError(t, err)
	// })
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestInitResignHappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperators(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	sk, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	owner := eth_crypto.PubkeyToAddress(sk.PublicKey)
	t.Run("test 4 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		// Construct resign message
		proofsData := wire.ConvertSignedProofsToSpec(proofs)
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err = clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 7 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		// Construct resign message
		proofsData := wire.ConvertSignedProofsToSpec(proofs)
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err = clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 10 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		// Construct resign message
		proofsData := wire.ConvertSignedProofsToSpec(proofs)
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err = clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 13 operators resign happy flow", func(t *testing.T) {
		id := spec.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = spec.NewID()
		// Construct resign message
		proofsData := wire.ConvertSignedProofsToSpec(proofs)
		reshareMsg, err := clnt.ConstructResignMessage(
			[]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133},
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			10,
			sk,
			proofsData)
		require.NoError(t, err)
		depositData, ks, proofs, err = clnt.StartResigning(id, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 10, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
