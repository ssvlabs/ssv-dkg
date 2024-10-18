package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

const EthRPC string = "https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz"

func TestReshareBulkJSONPArsing(t *testing.T) {
	reshareBytes, err := os.ReadFile(filepath.Clean("./stubs/reshare/bulk_reshare_msgs.json"))
	require.NoError(t, err)
	var bulkReshare wire.SignedBulkReshare
	err = json.Unmarshal(reshareBytes, &bulkReshare)
	require.NoError(t, err)
	t.Log("Reshare unmarshal", bulkReshare)

	bulkReshareMsgs, err := bulkReshare.MarshalReshareMessagesJSON()
	require.NoError(t, err)
	t.Log("Marshaled reshare messages", string(bulkReshareMsgs))

	var finalMsg []byte
	prefix := []byte("\x19Ethereum Signed Message:\n")
	msgLen := []byte(strconv.Itoa(len(bulkReshareMsgs)))
	finalMsg = append(finalMsg, prefix...)
	finalMsg = append(finalMsg, msgLen...)
	finalMsg = append(finalMsg, bulkReshareMsgs...)
	var hash [32]byte
	keccak256 := eth_crypto.Keccak256(finalMsg)
	copy(hash[:], keccak256)
	t.Log("Hash", hex.EncodeToString(hash[:]))
}

func TestResignBulkJSONPArsing(t *testing.T) {
	bulkResignBytes, err := os.ReadFile(filepath.Clean("./stubs/resign/bulk_resign_msgs.json"))
	require.NoError(t, err)
	var signedBulkResign wire.SignedBulkResign
	err = json.Unmarshal(bulkResignBytes, &signedBulkResign)
	require.NoError(t, err)

	bulkResignMsgs, err := signedBulkResign.MarshalResignMessagesJSON()
	require.NoError(t, err)
	t.Log("Marshaled reshare messages", string(bulkResignMsgs))

	var finalMsg []byte
	prefix := []byte("\x19Ethereum Signed Message:\n")
	msgLen := []byte(strconv.Itoa(len(bulkResignMsgs)))
	finalMsg = append(finalMsg, prefix...)
	finalMsg = append(finalMsg, msgLen...)
	finalMsg = append(finalMsg, bulkResignMsgs...)
	var hash [32]byte
	keccak256 := eth_crypto.Keccak256(finalMsg)
	copy(hash[:], keccak256)
	t.Log("Hash", hex.EncodeToString(hash[:]))
}

func TestVerifyMultisigSignedOnChain2of3(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")
		ethBackend, err := ethclient.Dial(EthRPC)
		require.NoError(t, err)

		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		msgLen := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, msgLen...)
		finalMsg = append(finalMsg, message...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))
		// 3 sigs concatenated
		encSigs, err := hex.DecodeString("e6cca66b0ce03f8049347ad9d8252f034fd538be62ddb4fc01dedccd723c7567050f8882aab359d9f5c13938ae8fa3a7109f4f5005630ef829b4683b7221377f1c6ef175759ce0e1890cdd57576e0216be371d528dfce7a27b1b843b12e49feed907d909ac1dfbd237499b8b504a8ea0ebce850987331cc56c208dc90c9c9d89601c")
		require.NoError(t, err)
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			encSigs))
	})
}

func TestVerifyMultisigSignedOnChain(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")
		ethBackend, err := ethclient.Dial(EthRPC)
		require.NoError(t, err)

		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		msgLen := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, msgLen...)
		finalMsg = append(finalMsg, message...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))

		require.NoError(t, err)
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			nil))
	})
}

func TestVerifyMultisigSignedOffChain(t *testing.T) {
	t.Run("valid Gnosis 2/3 miltisig offchain signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x43908b5794da9A8f714f001567D8dA1523e68bDb")
		ethBackend, err := ethclient.Dial(EthRPC)
		require.NoError(t, err)

		msg := "932ab87aee23606dd0c085cab46322ffed345a3aa028673c25f72b5d486e14e2"

		var finalMsg []byte
		prefix := []byte("\x19Ethereum Signed Message:\n")
		msgLen := []byte(strconv.Itoa(len(msg)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, msgLen...)
		finalMsg = append(finalMsg, msg...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		// signed with TS script here utils/gnosis_multisig_examples/safe_off_chain
		sig, err := hex.DecodeString("5b931ab4702f3712cfc791cf9bb88ce5b888ac6e3d9037e9867d926d696dd5d61831d98008f0a0b7d990ad8f049fe964e44ac5b8b800dd924354699d27ef6fa61ce5ce47d802cecc1e4158cb6a32159c60d2cbcdd29f5c811a5c389fc5e8b36fba3fb5c5284fb4ea3625b79e5f11396ad21a047d8c60ffc4076bf0e0f65e9ec6951c")
		require.NoError(t, err)
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			sig))
	})
}

func TestVerifyEOASigned(t *testing.T) {
	t.Run("valid EOA signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9")
		ethBackend, err := ethclient.Dial(EthRPC)
		require.NoError(t, err)

		msg := "a3703ef95414e008f95e9d0adb6e0122e70ea2a71459eeafe3382dd24ae03706"

		var finalMsg []byte
		prefix := []byte("\x19Ethereum Signed Message:\n")
		msgLen := []byte(strconv.Itoa(len(msg)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, msgLen...)
		finalMsg = append(finalMsg, msg...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256([]byte(finalMsg))
		copy(hash[:], keccak256)

		t.Log("Hash :", hex.EncodeToString(hash[:]))

		sk_path := "../examples/initiator/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9"
		password_path := "../examples/initiator/password"

		jsonBytes, err := os.ReadFile(sk_path)
		require.NoError(t, err)
		keyStorePassword, err := os.ReadFile(filepath.Clean(password_path))
		require.NoError(t, err)
		sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
		require.NoError(t, err)

		ownerSigBytes, err := eth_crypto.Sign(hash[:], sk.PrivateKey)
		require.NoError(t, err)

		t.Log("Sig :", hex.EncodeToString(ownerSigBytes))

		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			ownerSigBytes))
		sigFromMetamask, err := hex.DecodeString("ccb1866d30562f25cfb3d7001008667eba5fd76de2270cc32dc037ff7cd204f67c9f4fbfd47834bedb69a5907d8ef428dbb6fc706938866a01fe96763052758200")
		require.NoError(t, err)
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			sigFromMetamask))
	})
}
