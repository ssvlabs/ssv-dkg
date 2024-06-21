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
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
)

func TestReshareHappyFlow4OldOps(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb92b076fdd7dcfb209bec593abb1291ee9ddfe8ecab279dc851b06bcd3fb056872888f947e4b5f9d6df6703e547679e7/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 4 new disjoint operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test reshare 4 joint operators: 1 old + 3 new", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{11, 66, 77, 88}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test reshare 7 joint operators: 4 old + 3 new", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44}
		newIds := []uint64{11, 22, 33, 44, 55, 66, 77}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareHappyFlow7OldOps(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/7/000001-0xb4d29a4e25f152f77f76d5797b0dea319b03accee76565498d8b815a37c4db4d186c9e165f3e7eef9cebd503fd80d1ef/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 4 new disjoint operators", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77}
		newIds := []uint64{88, 99, 110, 111}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test reshare 4 joint operators: 1 old + 3 new", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77}
		newIds := []uint64{11, 88, 99, 110}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test reshare 10 joint operators: 7 old + 3 new", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77}
		newIds := []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareHappyFlow10OldOps(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/10/000001-0xb636059de70f3f09303b5a0cb19d34eea4f316b27312fb525ea0e6b2a281c466a3fa32bfc3e6f5163bfe6a97cac9f651/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 10->4: 4 old", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110}
		newIds := []uint64{11, 22, 33, 44}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			1)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 1, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareHappyFlow13OldOps(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/13/000001-0xa7cba4ab3690049ddfa3d453ff935dbfb0630c6996f3740354c01fbb1cebdf980a285e128d3963f46301e0d587766f66/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	t.Run("test reshare 13->4: 4 old", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113}
		newIds := []uint64{11, 22, 33, 44}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			1)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 1, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareThreshold4Ops(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/4/000001-0xb92b076fdd7dcfb209bec593abb1291ee9ddfe8ecab279dc851b06bcd3fb056872888f947e4b5f9d6df6703e547679e7/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	// kill old operators (operator ID: 11)
	servers[0].HttpSrv.Close()
	t.Run("test reshare 4 new disjoint operators", func(t *testing.T) {
		oldIds := []uint64{11, 22, 33, 44}
		newIds := []uint64{55, 66, 77, 88}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			oldIds,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			2)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 2, withdraw)
		require.NoError(t, err)
	})
	t.Run("test reshare 7 new joint operators", func(t *testing.T) {
		oldIds := []uint64{11, 22, 33, 44}
		newIds := []uint64{22, 33, 44, 55, 66, 77, 88}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			oldIds,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			2)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 2, withdraw)
		require.NoError(t, err)
	})
	t.Run("test reshare 10 new joint operators", func(t *testing.T) {
		oldIds := []uint64{11, 22, 33, 44}
		newIds := []uint64{22, 33, 44, 55, 66, 77, 88, 99, 110, 111}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			oldIds,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"holesky",
			withdraw.Bytes(),
			owner,
			2)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 2, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareThreshold7Ops(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/7/000001-0xb4d29a4e25f152f77f76d5797b0dea319b03accee76565498d8b815a37c4db4d186c9e165f3e7eef9cebd503fd80d1ef/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	// kill old operators (operator ID: 11; operator ID: 22)
	servers[0].HttpSrv.Close()
	servers[1].HttpSrv.Close()
	t.Run("test reshare 4 new disjoint operators", func(t *testing.T) {
		oldIds := []uint64{11, 22, 33, 44, 55, 66, 77}
		newIds := []uint64{88, 99, 110, 111}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			oldIds,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			0)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
func TestReshareThreshold10Ops(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/10/000001-0xb636059de70f3f09303b5a0cb19d34eea4f316b27312fb525ea0e6b2a281c466a3fa32bfc3e6f5163bfe6a97cac9f651/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	// kill old operators (operator ID: 11; operator ID: 22, operator ID: 33)
	servers[0].HttpSrv.Close()
	servers[1].HttpSrv.Close()
	servers[2].HttpSrv.Close()
	t.Run("test reshare 10->4: 4 old", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110}
		newIds := []uint64{77, 88, 99, 110}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			1)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 1, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestReshareThreshold13Ops(t *testing.T) {
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
	signedProofs, err := wire.LoadProofs("./stubs/13/000001-0xa7cba4ab3690049ddfa3d453ff935dbfb0630c6996f3740354c01fbb1cebdf980a285e128d3963f46301e0d587766f66/proofs.json")
	require.NoError(t, err)
	proofsData := wire.ConvertSignedProofsToSpec(signedProofs)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	// kill old operators (operator ID: 110; operator ID: 111, operator ID: 112, operator ID: 113)
	servers[9].HttpSrv.Close()
	servers[10].HttpSrv.Close()
	servers[11].HttpSrv.Close()
	servers[12].HttpSrv.Close()
	t.Run("test reshare 13->4: 4 old", func(t *testing.T) {
		ids := []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113}
		newIds := []uint64{11, 22, 33, 44}
		newId := spec.NewID()
		// construct reshare message and sign eip1271
		reshare, err := clnt.ConstructReshareMessage(
			ids,
			newIds,
			proofsData[0].Proof.ValidatorPubKey,
			"mainnet",
			withdraw.Bytes(),
			owner,
			1)
		require.NoError(t, err)
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)
		ownerSig, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)
		err = spec_crypto.VerifySignedMessageByOwner(stubClient,
			owner,
			reshare,
			ownerSig,
		)
		require.NoError(t, err)
		reshareMsg := &wire.ReshareMessage{
			SignedReshare: &spec.SignedReshare{
				Reshare:   *reshare,
				Signature: ownerSig,
			},
			Proofs: proofsData,
		}
		depositData, ks, proofs, err := clnt.StartResharing(newId, reshareMsg)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 1, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
