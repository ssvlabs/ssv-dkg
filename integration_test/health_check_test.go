package integration_test

import (
	"io"
	"os"
	"reflect"
	"strings"
	"testing"
	"unsafe"

	"github.com/ethereum/go-ethereum"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/dkg-spec/testing/stubs"
	cli_initiator "github.com/ssvlabs/ssv-dkg/cli/initiator"
)

func TestHealthCheck(t *testing.T) {
	// Not parallel — redirects os.Stdout
	stubClient := &stubs.Client{
		CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
			return nil, nil
		},
	}
	servers, _ := createOperators(t, testVersion, stubClient)
	t.Cleanup(func() {
		for _, srv := range servers {
			srv.HttpSrv.Close()
		}
	})
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
	RootCmd.Version = testVersion
	cli_initiator.HealthCheck.Version = testVersion
	t.Run("test 1 operator health check: positive", func(t *testing.T) {
		rescueStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		args := []string{"ping", "--ip", ips[0]}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		require.NoError(t, w.Close())
		out, _ := io.ReadAll(r)
		os.Stderr = rescueStderr
		t.Log(string(out))
		require.True(t, strings.Contains(string(out), "operator online and healthy: multisig ready 👌 and connected to ethereum network"))
		resetFlags(RootCmd)
	})
	t.Run("test 1 operator health check: negative", func(t *testing.T) {
		servers[0].HttpSrv.Close()
		rescueStderr := os.Stderr
		r, w, _ := os.Pipe()
		os.Stderr = w
		args := []string{"ping", "--ip", ips[0]}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		require.NoError(t, w.Close())
		out, _ := io.ReadAll(r)
		os.Stderr = rescueStderr
		t.Log(string(out))
		require.True(t, strings.Contains(string(out), "operator not healthy"))
		require.True(t, strings.Contains(string(out), "connection refused"))
		resetFlags(RootCmd)
	})
}

func resetFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Value.Type() == "stringSlice" {
			value := reflect.ValueOf(flag.Value).Elem().FieldByName("value")
			ptr := (*[]string)(unsafe.Pointer(value.Pointer())) //nolint:gosec // required to reset cobra flag internals
			*ptr = make([]string, 0)
		}
	})
	for _, cmd := range cmd.Commands() {
		resetFlags(cmd)
	}
}
