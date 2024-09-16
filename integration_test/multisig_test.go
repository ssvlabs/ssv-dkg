package integration_test

import (
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/stretchr/testify/require"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

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
	len := []byte(strconv.Itoa(len(bulkReshareMsgs)))
	finalMsg = append(finalMsg, prefix...)
	finalMsg = append(finalMsg, len...)
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
	len := []byte(strconv.Itoa(len(bulkResignMsgs)))
	finalMsg = append(finalMsg, prefix...)
	finalMsg = append(finalMsg, len...)
	finalMsg = append(finalMsg, bulkResignMsgs...)
	var hash [32]byte
	keccak256 := eth_crypto.Keccak256(finalMsg)
	copy(hash[:], keccak256)
	t.Log("Hash", hex.EncodeToString(hash[:]))
}

func TestVerifyMultisigSignedOnChain2of3(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")
		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)

		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
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
		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)

		var finalMsg []byte
		message := []byte("I am the owner of this Safe account")
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(message)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
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

func TestVerifyMultisigSignedBulkReshareOffChain(t *testing.T) {
	t.Run("valid Gnosis 2/3 miltisig offchain signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0xC4D860871fb983d17eC665a305e98F1B3035a817")
		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)

		reshareBytes, err := os.ReadFile(filepath.Clean("./stubs/reshare/bulk_reshare_msgs.json"))
		require.NoError(t, err)
		var signedBulkReshare wire.SignedBulkReshare
		err = json.Unmarshal(reshareBytes, &signedBulkReshare)
		require.NoError(t, err)
		t.Log("Reshare unmarshal", signedBulkReshare)

		bulkReshareMsgs, err := signedBulkReshare.MarshalReshareMessagesJSON()
		require.NoError(t, err)
		t.Log("Marshaled reshare messages", string(bulkReshareMsgs))

		var finalMsg []byte
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(bulkReshareMsgs)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
		finalMsg = append(finalMsg, bulkReshareMsgs...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))
		require.NoError(t, err)
		t.Log("Signature", hex.EncodeToString(signedBulkReshare.Signature[:]))
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			signedBulkReshare.Signature))
	})
}

func TestVerifyMultisigSignedBulkResignOffChain(t *testing.T) {
	t.Run("valid Gnosis 2/3 miltisig offchain signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0xC4D860871fb983d17eC665a305e98F1B3035a817")
		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)

		bulkResignBytes, err := os.ReadFile(filepath.Clean("./stubs/resign/bulk_resign_msgs.json"))
		require.NoError(t, err)
		var signedBulkResign wire.SignedBulkResign
		err = json.Unmarshal(bulkResignBytes, &signedBulkResign)
		require.NoError(t, err)

		bulkReshareMsgs, err := signedBulkResign.MarshalResignMessagesJSON()
		require.NoError(t, err)
		t.Log("Marshaled resign messages", string(bulkReshareMsgs))

		var finalMsg []byte
		prefix := []byte("\x19Ethereum Signed Message:\n")
		len := []byte(strconv.Itoa(len(bulkReshareMsgs)))

		finalMsg = append(finalMsg, prefix...)
		finalMsg = append(finalMsg, len...)
		finalMsg = append(finalMsg, bulkReshareMsgs...)
		var hash [32]byte
		keccak256 := eth_crypto.Keccak256(finalMsg)
		copy(hash[:], keccak256)
		t.Log("Hash", hex.EncodeToString(hash[:]))
		require.NoError(t, err)
		t.Log("Signature", hex.EncodeToString(signedBulkResign.Signature[:]))
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			signedBulkResign.Signature))
	})
}