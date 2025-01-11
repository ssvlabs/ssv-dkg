package integration_test

import (
	"crypto/ecdsa"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/dkg-spec/testing/stubs"
	cli_initiator "github.com/ssvlabs/ssv-dkg/cli/initiator"
	cli_verify "github.com/ssvlabs/ssv-dkg/cli/verify"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestBulkResignHappyFlows4Ops(t *testing.T) {
	err := os.RemoveAll("./data/output/")
	require.NoError(t, err)
	err = logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.GenerateResignMsg)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	// validate results
	initCeremonies, err := os.ReadDir("./stubs/bulk/4")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./stubs/bulk/4/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 4 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./stubs/bulk/4/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/4/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/4/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate resign message for signing
			generateResignMsgArgs := []string{"generate-resign-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--nonce", "10",
				"--amount", "32000000000"}
			RootCmd.SetArgs(generateResignMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load resign message
			resignMsgBytes, err := os.ReadFile("./data/output/resign.txt")
			require.NoError(t, err)

			// sign resign message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(resignMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"resign",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--nonce", "10",
				"--amount", "32000000000",
				"--signatures", signature,
				"--clientCACertPath", rootCert[0]}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove resign message
	err = os.Remove("./data/output/resign.txt")
	require.NoError(t, err)
	// validate resign results
	resignCeremonies, err := os.ReadDir("./data/output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./data/output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(10),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./data/output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkResignHappyFlows7Ops(t *testing.T) {
	err := os.RemoveAll("./data/output/")
	require.NoError(t, err)
	err = logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.GenerateResignMsg)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	// validate results
	initCeremonies, err := os.ReadDir("./stubs/bulk/7")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./stubs/bulk/7/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 7 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./stubs/bulk/7/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/7/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/7/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateResignMsgArgs := []string{"generate-resign-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--nonce", "10",
				"--amount", "32000000000"}
			RootCmd.SetArgs(generateResignMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load resign message
			resignMsgBytes, err := os.ReadFile("./data/output/resign.txt")
			require.NoError(t, err)

			// sign resign message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(resignMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"resign",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--nonce", "10",
				"--amount", "32000000000",
				"--signatures", signature,
				"--clientCACertPath", rootCert[0]}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove resign message
	err = os.Remove("./data/output/resign.txt")
	require.NoError(t, err)
	// validate resign results
	resignCeremonies, err := os.ReadDir("./data/output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./data/output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(10),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./data/output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkResignHappyFlows10Ops(t *testing.T) {
	err := os.RemoveAll("./data/output/")
	require.NoError(t, err)
	err = logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.GenerateResignMsg)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	// validate results
	initCeremonies, err := os.ReadDir("./stubs/bulk/10")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./stubs/bulk/10/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 10 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./stubs/bulk/10/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/10/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/10/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate resign message for signing
			generateResignMsgArgs := []string{"generate-resign-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110",
				"--nonce", "10",
				"--amount", "32000000000"}
			RootCmd.SetArgs(generateResignMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load resign message
			resignMsgBytes, err := os.ReadFile("./data/output/resign.txt")
			require.NoError(t, err)

			// sign resign message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(resignMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"resign",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110",
				"--nonce", "10",
				"--amount", "32000000000",
				"--signatures", signature,
				"--clientCACertPath", rootCert[0]}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove resign message
	err = os.Remove("./data/output/resign.txt")
	require.NoError(t, err)
	// validate resign results
	resignCeremonies, err := os.ReadDir("./data/output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./data/output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(10),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./data/output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkResingHappyFlows13Ops(t *testing.T) {
	err := os.RemoveAll("./data/output/")
	require.NoError(t, err)
	err = logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, ops := createOperatorsFromExamplesFolder(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.GenerateResignMsg)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	// validate results
	initCeremonies, err := os.ReadDir("./stubs/bulk/13")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify", "--ceremonyDir",
			"./stubs/bulk/13/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1),
			"--amount", "2048000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 13 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./stubs/bulk/13/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/13/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/13/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate resign message for signing
			generateResignMsgArgs := []string{"generate-resign-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110,111,112,113",
				"--nonce", "10",
				"--amount", "2048000000000"}
			RootCmd.SetArgs(generateResignMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load resign message
			resignMsgBytes, err := os.ReadFile("./data/output/resign.txt")
			require.NoError(t, err)

			// sign resign message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)

			signature, err := SignHash(string(resignMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"resign",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110,111,112,113",
				"--nonce", "10",
				"--amount", "2048000000000",
				"--signatures", signature,
				"--clientCACertPath", rootCert[0]}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove resign message
	err = os.Remove("./data/output/resign.txt")
	require.NoError(t, err)
	// validate resign results
	resignCeremonies, err := os.ReadDir("./data/output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./data/output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(10),
			"--amount", "2048000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./data/output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func SignResign(msg []*wire.ResignMessage, sk *ecdsa.PrivateKey) (string, error) {
	hash, err := utils.GetMessageHash(msg)
	if err != nil {
		return "", err
	}
	// Sign message root
	ownerSigBytes, err := eth_crypto.Sign(hash[:], sk)
	if err != nil {
		return "", err
	}
	signature := hex.EncodeToString(ownerSigBytes)

	return signature, nil
}

func SignHash(hexString string, sk *ecdsa.PrivateKey) (string, error) {
	hash := [32]byte{}
	var finalMsg []byte
	prefix := []byte("\x19Ethereum Signed Message:\n")
	msgLen := []byte(strconv.Itoa(len(hexString)))
	finalMsg = append(finalMsg, prefix...)
	finalMsg = append(finalMsg, msgLen...)
	finalMsg = append(finalMsg, hexString...)
	copy(hash[:], eth_crypto.Keccak256(finalMsg))
	// Sign message root
	ownerSigBytes, err := eth_crypto.Sign(hash[:], sk)
	if err != nil {
		return "", err
	}
	signature := hex.EncodeToString(ownerSigBytes)

	return signature, nil
}
