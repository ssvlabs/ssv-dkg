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
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	cli_initiator "github.com/ssvlabs/ssv-dkg/cli/initiator"
	cli_verify "github.com/ssvlabs/ssv-dkg/cli/verify"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestReshareThresholdOldValidators4Ops(t *testing.T) {
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
			"--nonce", strconv.Itoa(1),
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-share
	servers[0].HttpSrv.Close() // close ID 11
	t.Run("test 4 old operators reshare, 1 old operator off, threshold 3", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 10 || validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/4/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/4/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/4/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			signedProof, err := wire.LoadProofs(proofsFilePath)
			require.NoError(t, err)
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			logger := zap.L().Named("integration-tests")
			clnt, err := initiator.New(ops, logger, version, rootCert)
			require.NoError(t, err)
			reshareMsg, err := clnt.ConstructReshareMessage([]uint64{11, 22, 33, 44}, []uint64{22, 33, 44, 55}, signedProof[0][0].Proof.ValidatorPubKey, "holesky", common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494").Bytes(), common.HexToAddress("0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9"), 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProof[0])
			require.NoError(t, err)
			signature, err := SignReshare([]*wire.ReshareMessage{reshareMsg}, sk.PrivateKey)
			require.NoError(t, err)
			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44",
				"--newOperatorIDs", "22,33,44,55",
				"--nonce", strconv.Itoa(10),
				"--network", "holesky",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// validate reshare results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
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

func TestReshareThresholdOldValidators7Ops(t *testing.T) {
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
	servers[0].HttpSrv.Close() // close ID 11
	servers[1].HttpSrv.Close() // close ID 22
	t.Run("test 7 old operators reshare, 2 old operators off, threshold 5", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 10 || validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/7/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/7/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/7/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			signedProof, err := wire.LoadProofs(proofsFilePath)
			require.NoError(t, err)
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			logger := zap.L().Named("integration-tests")
			clnt, err := initiator.New(ops, logger, version, rootCert)
			require.NoError(t, err)
			reshareMsg, err := clnt.ConstructReshareMessage([]uint64{11, 22, 33, 44, 55, 66, 77}, []uint64{44, 55, 66, 77, 88, 99, 110}, signedProof[0][0].Proof.ValidatorPubKey, "holesky", common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494").Bytes(), common.HexToAddress("0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9"), 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProof[0])
			require.NoError(t, err)
			signature, err := SignReshare([]*wire.ReshareMessage{reshareMsg}, sk.PrivateKey)
			require.NoError(t, err)
			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77",
				"--newOperatorIDs", "44,55,66,77,88,99,110",
				"--nonce", strconv.Itoa(10),
				"--network", "holesky",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// validate reshare results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
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

func TestReshareThresholdOldValidators10Ops(t *testing.T) {
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
	servers[0].HttpSrv.Close() // close ID 11
	servers[1].HttpSrv.Close() // close ID 22
	servers[2].HttpSrv.Close() // close ID 33
	t.Run("test 10 old operators reshare, 3 old operators off, threshold 7", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 10 || validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/10/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/10/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/10/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			signedProof, err := wire.LoadProofs(proofsFilePath)
			require.NoError(t, err)
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			logger := zap.L().Named("integration-tests")
			clnt, err := initiator.New(ops, logger, version, rootCert)
			require.NoError(t, err)
			reshareMsg, err := clnt.ConstructReshareMessage([]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110}, []uint64{77, 88, 99, 110, 111, 112, 113}, signedProof[0][0].Proof.ValidatorPubKey, "holesky", common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494").Bytes(), common.HexToAddress("0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9"), 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProof[0])
			require.NoError(t, err)
			signature, err := SignReshare([]*wire.ReshareMessage{reshareMsg}, sk.PrivateKey)
			require.NoError(t, err)
			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110",
				"--newOperatorIDs", "77,88,99,110,111,112,113",
				"--nonce", strconv.Itoa(10),
				"--network", "holesky",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// validate reshare results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
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

func TestReshareThresholdOldValidators13Ops(t *testing.T) {
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
			"--amount", "32000000000"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-share
	servers[0].HttpSrv.Close() // close ID 11
	servers[1].HttpSrv.Close() // close ID 22
	servers[2].HttpSrv.Close() // close ID 33
	servers[3].HttpSrv.Close() // close ID 44
	t.Run("test 13 old operators reshare, 4 old operators off, threshold 9", func(t *testing.T) {
		for i, c := range initCeremonies {
			if validators[i] == 10 || validators[i] == 100 {
				continue
			}
			proofsFilePath := "./stubs/bulk/13/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./stubs/bulk/13/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./stubs/bulk/13/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			signedProof, err := wire.LoadProofs(proofsFilePath)
			require.NoError(t, err)
			jsonBytes, err := os.ReadFile("./stubs/UTC--2024-06-14T14-05-12.366668334Z--dcc846fa10c7cfce9e6eb37e06ed93b666cfc5e9")
			require.NoError(t, err)
			keyStorePassword, err := os.ReadFile(filepath.Clean("./stubs/password"))
			require.NoError(t, err)
			sk, err := keystore.DecryptKey(jsonBytes, string(keyStorePassword))
			require.NoError(t, err)
			logger := zap.L().Named("integration-tests")
			clnt, err := initiator.New(ops, logger, version, rootCert)
			require.NoError(t, err)
			reshareMsg, err := clnt.ConstructReshareMessage([]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 110, 111, 112, 113}, []uint64{77, 88, 99, 110, 111, 112, 113}, signedProof[0][0].Proof.ValidatorPubKey, "holesky", common.HexToAddress("0x81592c3de184a3e2c0dcb5a261bc107bfa91f494").Bytes(), common.HexToAddress("0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9"), 10, uint64(spec_crypto.MIN_ACTIVATION_BALANCE), signedProof[0])
			require.NoError(t, err)
			signature, err := SignReshare([]*wire.ReshareMessage{reshareMsg}, sk.PrivateKey)
			require.NoError(t, err)
			args := []string{"reshare",
				"--proofsFilePath", proofsFilePath,
				"--operatorsInfo", string(operators),
				"--owner", "0xDCc846fA10C7CfCE9e6Eb37e06eD93b666cFC5E9",
				"--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494",
				"--operatorIDs", "11,22,33,44,55,66,77,88,99,110,111,112,113",
				"--newOperatorIDs", "77,88,99,110,111,112,113",
				"--nonce", strconv.Itoa(10),
				"--network", "holesky",
				"--signatures", signature}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// validate reshare results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
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
