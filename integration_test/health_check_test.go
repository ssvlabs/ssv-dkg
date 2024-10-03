package integration_test

import (
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
	require.NoError(t, err)
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
	t.Run("test 4 operators health check", func(t *testing.T) {
		args := []string{"ping", "--ip", strings.Join(ips, ",")}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}
