package integration_test

import (
	"io"
	"os"
	"strings"
	"testing"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum"
	"github.com/spf13/cobra"
	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/dkg-spec/testing/stubs"
	cli_initiator "github.com/ssvlabs/ssv-dkg/cli/initiator"
)

func TestHealthCheck(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, _ := createOperators(t, version, stubClient)
	var ips []string
	for _, s := range servers {
		ips = append(ips, s.HttpSrv.URL)
	}
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.HealthCheck)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.HealthCheck.Version = version
	t.Run("test 1 operator health check: positive", func(t *testing.T) {
		rescueStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		args := []string{"ping", "--ip", ips[0]}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		w.Close()
		out, _ := io.ReadAll(r)
		os.Stdout = rescueStdout
		t.Log(string(out))
		require.True(t, strings.Contains(string(out), "operator online and healthy: multisig ready 👌 and connected to ethereum network"))
		resetFlags(RootCmd)
	})
	t.Run("test 1 operator health check: negative", func(t *testing.T) {
		servers[0].HttpSrv.Close()
		rescueStdout := os.Stdout
		r, w, _ := os.Pipe()
		os.Stdout = w
		args := []string{"ping", "--ip", ips[0]}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		w.Close()
		out, _ := io.ReadAll(r)
		os.Stdout = rescueStdout
		t.Log(string(out))
		require.True(t, strings.Contains(string(out), "operator not healthy"))
		require.True(t, strings.Contains(string(out), "connection refused"))
		resetFlags(RootCmd)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
