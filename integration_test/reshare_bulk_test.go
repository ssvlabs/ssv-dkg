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
	cli_initiator "github.com/ssvlabs/ssv-dkg/cli/initiator"
	cli_verify "github.com/ssvlabs/ssv-dkg/cli/verify"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/dkg-spec/testing/stubs"
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
	servers, ops := createOperators(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartReshare.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 4 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "1",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})

	t.Run("test 4 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "10",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// t.Run("test 4 operators 100 validator bulk happy flow", func(t *testing.T) {
	// 	args := []string{"init",
	// 		"--validators", "100",
	// 		"--operatorsInfo", string(operators),
	// 		"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
	// 		"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
	// 		"--operatorIDs", "11,22,33,44",
	// 		"--nonce", "1"}
	// 	RootCmd.SetArgs(args)
	// 	err := RootCmd.Execute()
	// 	require.NoError(t, err)
	// 	resetFlags(RootCmd)
	// })
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 4 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--newOperatorIDs", "55,66,77,88",
				"--nonce", "10"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.json")
			require.NoError(t, err)
			reshareMsg := make([]*wire.ReshareMessage, 0)
			err = json.Unmarshal(reshareMsgBytes, &reshareMsg)
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignReshare(reshareMsg, sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--newOperatorIDs", "55,66,77,88",
				"--nonce", "10",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// remove resign message
	err = os.Remove("./output/reshare.json")
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
			"--nonce", strconv.Itoa(10)}
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
	servers, ops := createOperators(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartReshare.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 7 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "1",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})

	t.Run("test 7 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "10",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 7 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "100",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 7 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--newOperatorIDs", "77,88,99,100,111,122,133",
				"--nonce", "10"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.json")
			require.NoError(t, err)
			reshareMsg := make([]*wire.ReshareMessage, 0)
			err = json.Unmarshal(reshareMsgBytes, &reshareMsg)
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignReshare(reshareMsg, sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--newOperatorIDs", "77,88,99,100,111,122,133",
				"--nonce", "10",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// remove resign message
	err = os.Remove("./output/reshare.json")
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
			"--nonce", strconv.Itoa(10)}
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
	servers, ops := createOperators(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartReshare.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 10 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "1",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77,88,99,100",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})

	t.Run("test 10 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "10",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77,88,99,100",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 10 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "100",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77,88,99,100",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 10 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,100",
				"--newOperatorIDs", "11,22,33,44",
				"--nonce", "10"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.json")
			require.NoError(t, err)
			reshareMsg := make([]*wire.ReshareMessage, 0)
			err = json.Unmarshal(reshareMsgBytes, &reshareMsg)
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignReshare(reshareMsg, sk.PrivateKey)
			require.NoError(t, err)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,100",
				"--newOperatorIDs", "11,22,33,44",
				"--nonce", "10",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// remove resign message
	err = os.Remove("./output/reshare.json")
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
			"--nonce", strconv.Itoa(10)}
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
	servers, ops := createOperators(t, version, stubClient)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.GenerateReshareMsg)
	RootCmd.AddCommand(cli_initiator.StartReshare)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartReshare.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 13 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "1",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})

	t.Run("test 13 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "10",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 13 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init",
			"--validators", "100",
			"--operatorsInfo", string(operators),
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133",
			"--nonce", "1"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify",
			"--ceremonyDir", "./output/" + c.Name(),
			"--validators", strconv.Itoa(validators[i]),
			"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
			"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
			"--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 13 operators bulk reshare", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}

			// generate reshare message for signing
			generateReshareMsgArgs := []string{"generate-reshare-msg",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133",
				"--newOperatorIDs", "11,22,33,44",
				"--nonce", "10"}
			RootCmd.SetArgs(generateReshareMsgArgs)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)

			// load reshare message
			reshareMsgBytes, err := os.ReadFile("./output/reshare.json")
			require.NoError(t, err)
			reshareMsg := make([]*wire.ReshareMessage, 0)
			err = json.Unmarshal(reshareMsgBytes, &reshareMsg)
			require.NoError(t, err)

			// sign reshare message
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			signature, err := SignReshare(reshareMsg, sk.PrivateKey)

			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133",
				"--newOperatorIDs", "11,22,33,44",
				"--nonce", "10",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// remove resign message
	err = os.Remove("./output/reshare.json")
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
			"--nonce", strconv.Itoa(10)}
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

func SignReshare(msg []*wire.ReshareMessage, sk *ecdsa.PrivateKey) (string, error) {
	hash, err := utils.GetMessageHash(msg)
	if err != nil {
		return "", err
	}
	// Sign message root
	ownerSigBytes, err := eth_crypto.Sign(hash[:], sk)
	if err != nil {
		return "", err
	}
	sig := hex.EncodeToString(ownerSigBytes)
	return sig, nil
}
