package integration_test

import (
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
	"go.uber.org/zap/zapcore"
	"go.uber.org/zap/zaptest/observer"

	"github.com/ssvlabs/dkg-spec/testing/stubs"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
)

func TestHealthCheck(t *testing.T) {
	t.Parallel()
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
	t.Run("positive", func(t *testing.T) {
		core, logs := observer.New(zap.DebugLevel)
		dkgInitiator, err := initiator.New(nil, zap.New(core), testVersion, nil, true)
		require.NoError(t, err)
		err = dkgInitiator.Ping([]string{ips[0]})
		require.NoError(t, err)
		matches := logs.FilterLevelExact(zapcore.InfoLevel).FilterMessageSnippet("operator online and healthy")
		require.GreaterOrEqual(t, matches.Len(), 1, "expected healthy operator log message")
	})
	t.Run("negative", func(t *testing.T) {
		servers[0].HttpSrv.Close()
		core, logs := observer.New(zap.DebugLevel)
		dkgInitiator, err := initiator.New(nil, zap.New(core), testVersion, nil, true)
		require.NoError(t, err)
		err = dkgInitiator.Ping([]string{ips[0]})
		require.NoError(t, err)
		matches := logs.FilterLevelExact(zapcore.ErrorLevel).FilterMessageSnippet("operator not healthy")
		require.GreaterOrEqual(t, matches.Len(), 1, "expected unhealthy operator log message")
	})
}
