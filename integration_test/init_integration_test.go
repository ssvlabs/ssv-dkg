package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"testing"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils/test_utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

var (
	rootCert     = []string{"./certs/rootCA.crt"}
	operatorCert = "./certs/localhost.crt"
	operatorKey  = "./certs/localhost.key"
)

func TestInitOperatorsThreshold(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	clnt, err := initiator.New(env.ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	env.servers[0].HttpSrv.Close()
	t.Run("test 4 operators init unhappy flow, 1 not reachable", func(t *testing.T) {
		id := spec.NewID()
		_, _, _, err := clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44}, "hoodi", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "some new operators returned errors, cant continue")
	})
}

func TestThreshold(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	clnt, err := initiator.New(env.ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	tests := []struct {
		name       string
		ids        []uint64
		belowCount int
	}{
		{"13 operators", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, 8},
		{"10 operators", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, 6},
		{"7 operators", []uint64{11, 22, 33, 44, 55, 66, 77}, 4},
		{"4 operators", []uint64{11, 22, 33, 44}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := spec.NewID()
			_, ks, _, err := clnt.StartDKG(id, eth1Creds(withdraw), tc.ids, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
			require.NoError(t, err)
			sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
			require.NoError(t, err)
			pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
			require.NoError(t, err)
			threshold := utils.GetThreshold(tc.ids)
			// below threshold
			belowKeys := make([]*rsa.PrivateKey, tc.belowCount)
			for i := range belowKeys {
				belowKeys[i] = env.servers[i].PrivKey
			}
			require.Less(t, len(belowKeys), threshold)
			err = testSharesData(env.ops, len(tc.ids), belowKeys, sharesDataSigned, pubkeyraw, owner, 0)
			require.ErrorContains(t, err, "could not reconstruct a valid signature")
			// at threshold
			thresholdKeys := make([]*rsa.PrivateKey, threshold)
			for i := range thresholdKeys {
				thresholdKeys[i] = env.servers[i].PrivKey
			}
			require.Equal(t, len(thresholdKeys), threshold)
			err = testSharesData(env.ops, len(tc.ids), thresholdKeys, sharesDataSigned, pubkeyraw, owner, 0)
			require.NoError(t, err)
		})
	}
}

func TestUnhappyFlows(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	ops := env.ops.Clone()
	ops = append(ops, wire.OperatorCLI{Addr: env.servers[12].HttpSrv.URL, ID: 133, PubKey: &env.servers[12].PrivKey.PublicKey},
		wire.OperatorCLI{Addr: env.servers[12].HttpSrv.URL, ID: 0, PubKey: &env.servers[12].PrivKey.PublicKey},
		wire.OperatorCLI{Addr: env.servers[12].HttpSrv.URL, ID: 144, PubKey: &env.servers[12].PrivKey.PublicKey},
		wire.OperatorCLI{Addr: env.servers[12].HttpSrv.URL, ID: 155, PubKey: &env.servers[12].PrivKey.PublicKey})
	clnt, err := initiator.New(ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := spec.NewID()
	depositData, ks, _, err := clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
	require.NoError(t, err)
	sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
	require.NoError(t, err)
	pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
	require.NoError(t, err)
	err = testSharesData(ops, 4, []*rsa.PrivateKey{env.servers[0].PrivKey, env.servers[1].PrivKey, env.servers[2].PrivKey, env.servers[3].PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
	require.NoError(t, err)
	err = crypto.ValidateDepositDataCLI(depositData, eth1Creds(withdraw))
	require.NoError(t, err)
	marshalledKs, err := json.Marshal(ks)
	require.NotEmpty(t, marshalledKs)
	require.NoError(t, err)
	t.Run("test wrong operators shares order at SSV payload", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := spec.NewID()
		_, ks, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		signatureOffset := phase0.SignatureLength
		pubKeysOffset := phase0.PublicKeyLength*13 + signatureOffset
		_ = utils.SplitBytes(sharesDataSigned[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
		encryptedKeys := utils.SplitBytes(sharesDataSigned[pubKeysOffset:], len(sharesDataSigned[pubKeysOffset:])/13)
		wrongOrderSharesData := make([]byte, 0)
		wrongOrderSharesData = append(wrongOrderSharesData, sharesDataSigned[:pubKeysOffset]...)
		for i := len(encryptedKeys) - 1; i >= 0; i-- {
			wrongOrderSharesData = append(wrongOrderSharesData, encryptedKeys[i]...)
		}
		err = testSharesData(ops, 13, []*rsa.PrivateKey{env.servers[12].PrivKey, env.servers[11].PrivKey, env.servers[10].PrivKey, env.servers[9].PrivKey, env.servers[8].PrivKey, env.servers[7].PrivKey, env.servers[6].PrivKey, env.servers[5].PrivKey, env.servers[4].PrivKey, env.servers[3].PrivKey, env.servers[2].PrivKey, env.servers[1].PrivKey, env.servers[0].PrivKey}, wrongOrderSharesData, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "shares order is incorrect")
	})
	t.Run("test same ID", func(t *testing.T) {
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "got init msg for existing instance")
	})
	t.Run("test wrong operator IDs", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := spec.NewID()
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{101, 66, 77, 88}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operator is not in given operator data list")
	})
	t.Run("test non 3f+1 operator set", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := spec.NewID()
		// 0 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13: got 0")
		// 1 op
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13: got 1")
		// 2 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13: got 2")
		// 3 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13: got 3")
		// op with zero ID
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{0, 11, 22, 33}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operator ID cannot be 0")
		// 14 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133, 144}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13: got 14")
		// 15 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133, 144, 155}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13: got 15")
		// 5 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44, 55}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 6 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44, 55, 66}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 8 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{11, 22, 33, 44, 55, 66, 77, 88}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 9 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 11 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 12 ops
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
	})
	t.Run("test out of order operators (i.e 3,2,4,1) ", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := spec.NewID()
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 22, 44, 11}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 22, 44, 11, 100, 111, 122}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 22, 44, 11, 100, 111, 122, 99, 88, 77}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 22, 44, 11, 100, 111, 122, 99, 88, 77, 66, 55, 133}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 33, 44, 11}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators ids should be unique in the list")
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 22, 44, 22, 100, 111, 122, 99, 88, 77}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators ids should be unique in the list")
		_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{33, 22, 44, 11, 100, 111, 122, 99, 88, 77, 66, 55, 111}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
		require.ErrorContains(t, err, "operators ids should be unique in the list")
	})
}

func TestLargeOperatorIDs(t *testing.T) {
	t.Parallel()
	ids := []uint64{1100, 2222, 3300, 4444, 5555, 6666, 7777, 8888, 9999, 10000, 11111, 12222, 13333}
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsWithIDs(t, ids, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	clnt, err := initiator.New(ops, zap.L().Named("integration-tests"), testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := spec.NewID()
	depositData, ks, proofs, err := clnt.StartDKG(id, eth1Creds(withdraw), ids, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
	require.NoError(t, err)
	err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
	require.NoError(t, err)
}

func TestWrongInitiatorVersion(t *testing.T) {
	t.Parallel()
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsWithIDs(t, []uint64{1, 2, 3, 4}, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	clnt, err := initiator.New(ops, zap.L().Named("integration-tests"), "v1.0.0", rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := spec.NewID()
	_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{1, 2, 3, 4}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
	require.ErrorContains(t, err, "wrong version")
}

func TestWrongOperatorVersion(t *testing.T) {
	t.Parallel()
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	// First operator with wrong version, rest with correct version
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.0", operatorCert, operatorKey, stubClient)
	servers := []*test_utils.TestOperator{srv1}
	ops := wire.OperatorsCLI{{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey}}
	for _, id := range []uint64{2, 3, 4} {
		srv := test_utils.CreateTestOperator(t, id, testVersion, operatorCert, operatorKey, stubClient)
		ops = append(ops, wire.OperatorCLI{Addr: srv.HttpSrv.URL, ID: id, PubKey: &srv.PrivKey.PublicKey})
		servers = append(servers, srv)
	}
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
	clnt, err := initiator.New(ops, zap.L().Named("integration-tests"), testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := spec.NewID()
	_, _, _, err = clnt.StartDKG(id, eth1Creds(withdraw), []uint64{1, 2, 3, 4}, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
	require.ErrorContains(t, err, "wrong version")
}

func testSharesData(ops wire.OperatorsCLI, operatorCount int, keys []*rsa.PrivateKey, sharesData, validatorPublicKey []byte, owner common.Address, nonce uint16) error {
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("shares data len is not correct")
	}
	signature := sharesData[:signatureOffset]
	msg := []byte("Hello")
	err := crypto.VerifyOwnerNonceSignature(signature, owner, validatorPublicKey, nonce)
	if err != nil {
		return err
	}
	_ = utils.SplitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := utils.SplitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	sigs2 := make(map[uint64][]byte)
	opsIDs := make([]uint64, 0)
	for i, enck := range encryptedKeys {
		if len(keys) <= i {
			continue
		}
		priv := keys[i]

		share, err := spec_crypto.Decrypt(priv, enck)
		if err != nil {
			return err
		}
		secret := &bls.SecretKey{}
		err = secret.SetHexString(string(share))
		if err != nil {
			return err
		}
		// Find operator ID by PubKey
		var operatorID uint64
		for _, op := range ops {
			if bytes.Equal(priv.N.Bytes(), op.PubKey.N.Bytes()) {
				operatorID = op.ID
				break
			}
		}
		sig := secret.SignByte(msg)
		sigs2[operatorID] = sig.Serialize()

		// operators encoded shares should be ordered in increasing manner
		for _, op := range ops {
			if op.PubKey == &priv.PublicKey {
				opsIDs = append(opsIDs, op.ID)
			}
		}
	}
	// check if operators ordered correctly
	k := uint64(0)
	for _, i := range opsIDs {
		if i > k {
			k = i
		} else {
			return fmt.Errorf("shares order is incorrect")
		}
	}
	recon, err := ReconstructSignatures(sigs2)
	if err != nil {
		return err
	}
	err = VerifyReconstructedSignature(recon, validatorPublicKey, msg)
	if err != nil {
		return err
	}
	return nil
}

// ReconstructSignatures receives a map of user indexes and serialized bls.Sign.
// It then reconstructs the original threshold signature using lagrange interpolation
func ReconstructSignatures(signatures map[uint64][]byte) (*bls.Sign, error) {
	reconstructedSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for index, signature := range signatures {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", index))
		if err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		blsSig := bls.Sign{}

		err = blsSig.Deserialize(signature)
		if err != nil {
			return nil, err
		}
		sigVec = append(sigVec, blsSig)
	}
	err := reconstructedSig.Recover(sigVec, idVec)
	return &reconstructedSig, err
}

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey, msg []byte) error {
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(validatorPubKey); err != nil {
		return errors.Wrap(err, "could not deserialize validator pk")
	}
	// verify reconstructed sig
	if res := sig.VerifyByte(pk, msg); !res {
		return errors.New("could not reconstruct a valid signature")
	}
	return nil
}

func newEthAddress(t *testing.T) common.Address {
	privateKey, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	address := eth_crypto.PubkeyToAddress(*publicKeyECDSA)
	return address
}

var defaultOperatorIDs = []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}

var exampleOperatorIDs = []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113}

func createOperatorsWithIDs(t *testing.T, ids []uint64, version string, stubClient *stubs.Client) ([]*test_utils.TestOperator, wire.OperatorsCLI) {
	t.Helper()
	var servers []*test_utils.TestOperator
	var ops wire.OperatorsCLI
	for _, id := range ids {
		srv := test_utils.CreateTestOperator(t, id, version, operatorCert, operatorKey, stubClient)
		ops = append(ops, wire.OperatorCLI{Addr: srv.HttpSrv.URL, ID: id, PubKey: &srv.PrivKey.PublicKey})
		servers = append(servers, srv)
	}
	return servers, ops
}

func createOperators(t *testing.T, version string, stubClient *stubs.Client) ([]*test_utils.TestOperator, wire.OperatorsCLI) {
	return createOperatorsWithIDs(t, defaultOperatorIDs, version, stubClient)
}

func createOperatorsFromExamplesFolder(t *testing.T, version string, stubClient *stubs.Client) ([]*test_utils.TestOperator, wire.OperatorsCLI) {
	t.Helper()
	var servers []*test_utils.TestOperator
	var ops wire.OperatorsCLI
	for i, id := range exampleOperatorIDs {
		srv := test_utils.CreateTestOperatorFromFile(t, id, fmt.Sprintf("../examples/operator%d", i+1), version, operatorCert, operatorKey, stubClient)
		ops = append(ops, wire.OperatorCLI{Addr: srv.HttpSrv.URL, ID: id, PubKey: &srv.PrivKey.PublicKey})
		servers = append(servers, srv)
	}
	return servers, ops
}

func TestCompoundingWithdrawalCredentials(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	clnt, err := initiator.New(env.ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	tests := []struct {
		name string
		ids  []uint64
	}{
		{"4 operators 0x02", []uint64{11, 22, 33, 44}},
		{"7 operators 0x02", []uint64{11, 22, 33, 44, 55, 66, 77}},
		{"10 operators 0x02", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}},
		{"13 operators 0x02", []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			id := spec.NewID()
			// Pass 32-byte 0x02 compounding credentials
			compoundingCreds := spec_crypto.WithdrawalCredentials(spec_crypto.CompoundingWithdrawalPrefix, withdraw.Bytes())
			depositData, ks, proofs, err := clnt.StartDKG(id, compoundingCreds, tc.ids, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
			require.NoError(t, err)
			// Verify deposit data has 0x02 prefix in withdrawal credentials
			withdrawCreds, err := hex.DecodeString(depositData.WithdrawalCredentials)
			require.NoError(t, err)
			require.Len(t, withdrawCreds, 32)
			require.Equal(t, byte(0x02), withdrawCreds[0], "withdrawal credentials should have 0x02 prefix")
			require.Equal(t, withdraw.Bytes(), withdrawCreds[12:], "withdrawal credentials should contain the withdrawal address")
			// Validate full results
			err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
			require.NoError(t, err)
		})
	}
}

func TestCompoundingVsETH1DifferentCredentials(t *testing.T) {
	t.Parallel()
	env := setupDynamicTest(t)
	clnt, err := initiator.New(env.ops, env.logger, testVersion, rootCert, false)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	ids := []uint64{11, 22, 33, 44}
	// Run DKG with 0x01 credentials
	id1 := spec.NewID()
	dd01, _, _, err := clnt.StartDKG(id1, eth1Creds(withdraw), ids, "mainnet", owner, 0, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
	require.NoError(t, err)
	// Run DKG with 0x02 credentials (32-byte compounding)
	id2 := spec.NewID()
	compoundingCreds := spec_crypto.WithdrawalCredentials(spec_crypto.CompoundingWithdrawalPrefix, withdraw.Bytes())
	dd02, _, _, err := clnt.StartDKG(id2, compoundingCreds, ids, "mainnet", owner, 1, uint64(spec_crypto.MIN_ACTIVATION_BALANCE))
	require.NoError(t, err)
	// Verify they produce different withdrawal credentials
	require.NotEqual(t, dd01.WithdrawalCredentials, dd02.WithdrawalCredentials, "0x01 and 0x02 credentials should differ")
	// Verify the prefixes
	creds01, err := hex.DecodeString(dd01.WithdrawalCredentials)
	require.NoError(t, err)
	require.Equal(t, byte(0x01), creds01[0])
	creds02, err := hex.DecodeString(dd02.WithdrawalCredentials)
	require.NoError(t, err)
	require.Equal(t, byte(0x02), creds02[0])
	// The address portion should be the same
	require.Equal(t, creds01[12:], creds02[12:])
}
