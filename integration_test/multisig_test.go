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

func TestVerifyMultisigSigned3of3(t *testing.T) {
	t.Run("valid Gnosis 3/3 miltisig signatures", func(t *testing.T) {
		gnosisAddress := common.HexToAddress("0x0205c708899bde67330456886a05Fe30De0A79b6")
		ethBackend, err := ethclient.Dial("https://eth-sepolia.g.alchemy.com/v2/YyqRIEgydRXKTTT-w_0jtKSAH6sfr8qz")
		require.NoError(t, err)

		reshareBytes, err := os.ReadFile(filepath.Clean("./stubs/reshare/reshare_msgs.json"))
		require.NoError(t, err)
		var reshareMsgs []wire.Reshare
		err = json.Unmarshal(reshareBytes, &reshareMsgs)
		require.NoError(t, err)
		t.Log("Reshare", reshareMsgs)

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
		encSigs, err := hex.DecodeString("e6cca66b0ce03f8049347ad9d8252f034fd538be62ddb4fc01dedccd723c7567050f8882aab359d9f5c13938ae8fa3a7109f4f5005630ef829b4683b7221377f1c6ef175759ce0e1890cdd57576e0216be371d528dfce7a27b1b843b12e49feed907d909ac1dfbd237499b8b504a8ea0ebce850987331cc56c208dc90c9c9d89601c7456f55438bfa68016e710e5053a4a7fb0e4108af09c29f9f43bd21c315bba9616ac391f74b3f3e931e4c358b2058c028296d0b364bd43065d47ba72761663aa1c")
		require.NoError(t, err)
		require.NoError(t, spec_crypto.VerifySignedMessageByOwner(ethBackend,
			gnosisAddress,
			hash,
			encSigs))
	})
}
