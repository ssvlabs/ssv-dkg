package operator

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"testing"
	"time"

	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/dkg"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func singleOperatorKeys(t *testing.T, num int) *rsa.PrivateKey {
	privKey, err := os.ReadFile(filepath.Clean("../../examples/operator" + strconv.Itoa(num) + "/encrypted_private_key.json"))
	require.NoError(t, err)
	pass, err := os.ReadFile(filepath.Clean("../../examples/operator" + strconv.Itoa(num) + "/password"))
	require.NoError(t, err)
	priv, err := crypto.DecryptRSAKeystore(privKey, string(pass))
	require.NoError(t, err)
	return priv
}

func generateOperatorsData(t *testing.T, numOps int) ([]*rsa.PrivateKey, []*spec.Operator) {
	keys := make([]*rsa.PrivateKey, 0)
	ops := make([]*spec.Operator, 0)
	for i := 1; i <= numOps; i++ {
		priv := singleOperatorKeys(t, i)
		keys = append(keys, priv)
		oppkbytes, err := spec_crypto.EncodeRSAPublicKey(&priv.PublicKey)
		require.NoError(t, err)
		ops = append(ops, &spec.Operator{
			ID:     uint64(i),
			PubKey: oppkbytes,
		})
	}
	return keys, ops
}

func TestCreateInstance(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("state-tests")
	testCreateInstance := func(t *testing.T, numOps int) {
		privateKey, ops := generateOperatorsData(t, numOps)
		tempDir, err := os.MkdirTemp("", "dkg")
		require.NoError(t, err)
		s, err := New(privateKey[0], logger, []byte("test.version"), 1, tempDir, "http://ethnode:8545")
		require.NoError(t, err)
		var reqID [24]byte
		copy(reqID[:], "testRequestID1234567890") // Just a sample value
		_, pv, err := rsaencryption.GenerateKeys()
		require.NoError(t, err)
		priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
		require.NoError(t, err)
		init := &spec.Init{
			Operators: ops,
			Owner:     common.HexToAddress("0x0000000"),
			Nonce:     1,
		}

		inst, resp, err := s.State.CreateInstance(reqID, init.Operators, init, &priv.PublicKey)

		require.NoError(t, err)
		require.NotNil(t, inst)
		require.NotNil(t, resp)

		wrapper, ok := inst.(*instWrapper)
		require.True(t, ok)
		require.True(t, wrapper.LocalOwner.OperatorSecretKey.PublicKey.Equal(&privateKey[0].PublicKey))
	}

	testParams := []struct {
		ops int
	}{
		{4},
		{7},
		{13},
	}

	for _, param := range testParams {
		t.Run(fmt.Sprintf("Test create instance with %v operators", param.ops), func(t *testing.T) {
			testCreateInstance(t, param.ops)
		})
	}
}

func TestInitInstance(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("state-tests")
	privateKey, ops := generateOperatorsData(t, 4)
	require.NoError(t, err)
	tempDir, err := os.MkdirTemp("", "dkg")
	require.NoError(t, err)
	swtch, err := New(privateKey[0], logger, []byte("test.version"), 1, tempDir, "http://ethnode:8545")
	require.NoError(t, err)
	var reqID [24]byte
	copy(reqID[:], "testRequestID1234567890") // Just a sample value

	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	encPubKey, err := spec_crypto.EncodeRSAPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	init := &spec.Init{
		// Populate the Init message fields as needed for testing
		// For example:
		Operators:             ops,
		Owner:                 common.HexToAddress("0x0000001"),
		Nonce:                 1,
		Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		T:                     3,
		WithdrawalCredentials: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
	}

	initmsg, err := init.MarshalSSZ()
	require.NoError(t, err)
	version := "test.version"
	initMessage := &wire.Transport{
		Type:       wire.InitMessageType,
		Identifier: reqID,
		Data:       initmsg,
		Version:    []byte(version),
	}
	tsssz, err := initMessage.MarshalSSZ()
	require.NoError(t, err)
	sig, err := spec_crypto.SignRSA(priv, tsssz)
	require.NoError(t, err)

	resp, err := swtch.State.InitInstance(reqID, initMessage, encPubKey, sig)
	require.NoError(t, err)
	require.NotNil(t, resp)

	require.Len(t, swtch.State.Instances, 1)

	resp2, err2 := swtch.State.InitInstance(reqID, initMessage, encPubKey, sig)
	require.Equal(t, err2, utils.ErrAlreadyExists)
	require.Nil(t, resp2)

	var tested = false
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(encPubKey)
	require.NoError(t, err)
	for i := 0; i < MaxInstances; i++ {
		reqIDx := [24]byte{}
		_, err := rand.Read(reqIDx[:]) // Just a sample value
		require.NoError(t, err)
		respx, errx := func(reqID [24]byte, initMsg *wire.Transport, initiatorPub, initiatorSignature []byte) ([]byte, error) {
			if err := swtch.State.validateInstances(reqID); err != nil {
				return nil, err
			}
			if err != nil {
				return nil, fmt.Errorf("init: failed to create instance: %s", err.Error())
			}
			swtch.State.Mtx.Lock()
			swtch.State.Instances[reqID] = &instWrapper{&dkg.LocalOwner{}, initiatorPubKey, make(chan []byte, 1)}
			swtch.State.InstanceInitTime[reqID] = time.Now()
			swtch.State.Mtx.Unlock()
			return resp, nil
		}(reqIDx, initMessage, encPubKey, sig)
		if i == MaxInstances-1 {
			require.Equal(t, errx, utils.ErrMaxInstances)
			require.Nil(t, respx)
			tested = true
			break
		}
	}

	require.True(t, tested)

	swtch.State.InstanceInitTime[reqID] = time.Now().Add(-2 * time.Minute)

	_, resp, err = swtch.State.CreateInstance(reqID, init.Operators, init, &priv.PublicKey)
	require.NoError(t, err)
	require.NotNil(t, resp)

}

func TestSwitch_cleanInstances(t *testing.T) {
	privateKey, ops := generateOperatorsData(t, 4)
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("state-tests")
	operatorPubKey := privateKey[0].Public().(*rsa.PublicKey)
	pkBytes, err := spec_crypto.EncodeRSAPublicKey(operatorPubKey)
	require.NoError(t, err)
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	swtch := NewSwitch(privateKey[0], logger, []byte("test.version"), pkBytes, 1, stubClient)
	var reqID [24]byte
	copy(reqID[:], "testRequestID1234567890") // Just a sample value
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	encPubKey, err := spec_crypto.EncodeRSAPublicKey(&priv.PublicKey)
	require.NoError(t, err)

	init := &spec.Init{
		// Populate the Init message fields as needed for testing
		// For example:
		Operators:             ops,
		Owner:                 common.HexToAddress("0x0000001"),
		Nonce:                 1,
		Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
		WithdrawalCredentials: []byte{1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1},
		T:                     3,
	}

	initmsg, err := init.MarshalSSZ()
	require.NoError(t, err)
	version := "test.version"
	initMessage := &wire.Transport{
		Type:       wire.InitMessageType,
		Identifier: reqID,
		Data:       initmsg,
		Version:    []byte(version),
	}
	tsssz, err := initMessage.MarshalSSZ()
	require.NoError(t, err)
	sig, err := spec_crypto.SignRSA(priv, tsssz)
	require.NoError(t, err)
	resp, err := swtch.InitInstance(reqID, initMessage, encPubKey, sig)
	require.NoError(t, err)
	require.NotNil(t, resp)
	require.Equal(t, swtch.cleanInstances(), 0)

	require.Len(t, swtch.Instances, 1)
	swtch.InstanceInitTime[reqID] = time.Now().Add(-time.Minute * 6)

	require.Equal(t, swtch.cleanInstances(), 1)
	require.Len(t, swtch.Instances, 0)

}

func TestCrashByMaliciousOperatorAtInit(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("state-tests")
	privateKey, ops := generateOperatorsData(t, 12)
	tempDir, err := os.MkdirTemp("", "dkg")
	require.NoError(t, err)
	s, err := New(privateKey[0], logger, []byte("test.version"), 1, tempDir, "http://ethnode:8545")
	require.NoError(t, err)
	var reqID [24]byte
	copy(reqID[:], "testRequestID1234567890") // Just a sample value
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	init := &spec.Init{
		Operators: ops,
		Owner:     common.HexToAddress("0x0000000"),
		Nonce:     1,
	}

	inst, resp, err := s.State.CreateInstance(reqID, init.Operators, init, &priv.PublicKey)

	require.NoError(t, err)
	require.NotNil(t, inst)
	require.NotNil(t, resp)

	wrapper, ok := inst.(*instWrapper)
	require.True(t, ok)
	require.True(t, wrapper.LocalOwner.OperatorSecretKey.PublicKey.Equal(&privateKey[0].PublicKey))

	// create multiple transport with wrong
	exchMsg := wire.Exchange{
		PK:      []byte{},
		Commits: []byte{},
	}
	sszExch, err := exchMsg.MarshalSSZ()
	require.NoError(t, err)
	ts := &wire.Transport{
		Type:       wire.ReshareExchangeMessageType,
		Identifier: reqID,
		Data:       sszExch,
		Version:    []byte("test.version"),
	}
	tsssz, err := ts.MarshalSSZ()
	require.NoError(t, err)

	sig, err := spec_crypto.SignRSA(privateKey[0], tsssz)
	require.NoError(t, err)

	opPubBytes, err := spec_crypto.EncodeRSAPublicKey(&privateKey[0].PublicKey)
	require.NoError(t, err)

	signedTransportMsg := &wire.SignedTransport{
		Message:   ts,
		Signer:    opPubBytes,
		Signature: sig,
	}
	err = wrapper.Process(signedTransportMsg, ops)
	require.ErrorContains(t, err, "failed to get reshare object at owner")
}

func TestCrashByMaliciousOperatorAtReshare(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("state-tests")
	privateKey, ops := generateOperatorsData(t, 12)
	tempDir, err := os.MkdirTemp("", "dkg")
	require.NoError(t, err)
	s, err := New(privateKey[0], logger, []byte("test.version"), 1, tempDir, "http://ethnode:8545")
	require.NoError(t, err)
	var reqID [24]byte
	copy(reqID[:], "testRequestID1234567890") // Just a sample value
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	signedProofs, err := wire.LoadProofs("../../integration_test/stubs/bulk/4/ceremony-2024-10-21--09-56-54.375/000001-0x801bca4e379a2e240ed004acbe8f905a0a43f3322faa251fbb9c8d4d49af8ba9c669e930ea7caa234cb7d537d600e9ee/proofs.json")
	require.NoError(t, err)
	reshare := &wire.ReshareMessage{
		Reshare: &spec.Reshare{
			ValidatorPubKey: signedProofs[0][0].Proof.ValidatorPubKey,
			NewOperators:    ops[:4],
			OldOperators:    ops[4:8],
			Owner:           common.HexToAddress("0xdcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9"),
			Nonce:           1,
		},
		Proofs: signedProofs[0],
	}

	inst, resp, err := s.State.CreateInstance(reqID, ops, reshare, &priv.PublicKey)

	require.NoError(t, err)
	require.NotNil(t, inst)
	require.NotNil(t, resp)

	wrapper, ok := inst.(*instWrapper)
	require.True(t, ok)
	require.True(t, wrapper.LocalOwner.OperatorSecretKey.PublicKey.Equal(&privateKey[0].PublicKey))

	// create multiple transport with wrong
	exchMsg := wire.Exchange{
		PK:      []byte{},
		Commits: []byte{},
	}
	sszExch, err := exchMsg.MarshalSSZ()
	require.NoError(t, err)
	ts := &wire.Transport{
		Type:       wire.ExchangeMessageType,
		Identifier: reqID,
		Data:       sszExch,
		Version:    []byte("test.version"),
	}
	tsssz, err := ts.MarshalSSZ()
	require.NoError(t, err)

	sig, err := spec_crypto.SignRSA(privateKey[0], tsssz)
	require.NoError(t, err)

	opPubBytes, err := spec_crypto.EncodeRSAPublicKey(&privateKey[0].PublicKey)
	require.NoError(t, err)

	signedTransportMsg := &wire.SignedTransport{
		Message:   ts,
		Signer:    opPubBytes,
		Signature: sig,
	}
	err = wrapper.Process(signedTransportMsg, ops)
	require.ErrorContains(t, err, "failed to get init object at owner")
}
