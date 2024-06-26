package integration_test

import (
	"encoding/json"
	"os"
	"strconv"
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/spf13/cobra"
	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/stretchr/testify/require"

	cli_initiator "github.com/bloxapp/ssv-dkg/cli/initiator"
	cli_verify "github.com/bloxapp/ssv-dkg/cli/verify"
	"github.com/bloxapp/ssv/logging"
)

func TestBulkHappyFlows4Ops(t *testing.T) {
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
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 4 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})

	t.Run("test 4 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 4 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
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
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
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

func TestBulkHappyFlows7Ops(t *testing.T) {
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
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 7 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 7 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 7 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
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
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
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

func TestBulkHappyFlows10Ops(t *testing.T) {
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
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 10 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 10 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 10 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
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
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
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

func TestBulkHappyFlows13Ops(t *testing.T) {
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
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 13 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 13 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 13 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
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
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
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
