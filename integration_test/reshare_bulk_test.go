package integration_test

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strconv"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/keystore"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/dkg-spec/testing/stubs"
	cli_initiator "github.com/ssvlabs/ssv-dkg/cli/initiator"
	cli_verify "github.com/ssvlabs/ssv-dkg/cli/verify"
)

func TestBulkReshareHappyFlows4Ops(t *testing.T) {
	err := os.RemoveAll("./output/")
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
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartReshare.Version = version
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
			"--nonce", strconv.Itoa(1), "--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-share
	t.Run("test 4 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./stubs/bulk/4/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/4/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/4/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--newOperatorIDs", "55,66,77,88",
				"--nonce", "10",
				"--amount", "32000000000"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.txt")
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(reshareMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--newOperatorIDs", "55,66,77,88",
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
	// remove reshare message
	err = os.Remove("./output/reshare.txt")
	require.NoError(t, err)
	// validate reshare results
	reshareCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range reshareCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
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
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkReshareHappyFlows7Ops(t *testing.T) {
	err := os.RemoveAll("./output/")
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
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartReshare.Version = version
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
	// re-share
	t.Run("test 7 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/7/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/7/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/7/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--newOperatorIDs", "77,88,99,110,111,112,113",
				"--nonce", "10",
				"--amount", "32000000000"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.txt")
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(reshareMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--newOperatorIDs", "77,88,99,110,111,112,113",
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
	// remove reshare message
	err = os.Remove("./output/reshare.txt")
	require.NoError(t, err)
	// validate reshare results
	reshareCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range reshareCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
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
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkReshareHappyFlows10Ops(t *testing.T) {
	err := os.RemoveAll("./output/")
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
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartReshare.Version = version
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
	// re-share
	t.Run("test 10 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/10/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/10/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/10/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110",
				"--newOperatorIDs", "11,22,33,44",
				"--nonce", "10",
				"--amount", "32000000000"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.txt")
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(reshareMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110",
				"--newOperatorIDs", "11,22,33,44",
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
	// remove reshare message
	err = os.Remove("./output/reshare.txt")
	require.NoError(t, err)
	// validate reshare results
	reshareCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range reshareCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
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
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkReshareHappyFlows13Ops(t *testing.T) {
	err := os.RemoveAll("./output/")
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
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartReshare.Version = version
	cli_verify.Verify.Version = version
	// validate results
	initCeremonies, err := os.ReadDir("./stubs/bulk/13")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./stubs/bulk/13/" + c.Name(),
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
	// re-share
	t.Run("test 13 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/13/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/13/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/13/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110,111,112,113",
				"--newOperatorIDs", "11,22,33,44",
				"--nonce", "10",
				"--amount", "2048000000000"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.txt")
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignHash(string(reshareMsgBytes), sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110,111,112,113",
				"--newOperatorIDs", "11,22,33,44",
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
	err = os.Remove("./output/reshare.txt")
	require.NoError(t, err)
	// validate reshare results
	reshareCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range reshareCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
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
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
