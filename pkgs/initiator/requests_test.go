package initiator_test

// Regression tests for how operator responses are presented to the user.
//
// The invariant under test: an error an operator actually reported is passed on as itself,
// without a diagnosis the initiator is in no position to make.

import (
	"errors"
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// failingOperator serves one wire-encoded error at the given status for every request.
func failingOperator(t *testing.T, status int, body []byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		writer.WriteHeader(status)
		_, err := writer.Write(body)
		require.NoError(t, err)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// TestSendAndCollectDoesNotBlameOperatorVersion asserts a ceremony failure an operator
// deliberately reported is not re-labelled as a version problem.
//
// The ceremony routes answer failures with a fixed code that carries no detail. Prefixing
// that with an upgrade instruction leaves the operator reading a message whose only
// actionable-looking words are a diagnosis nothing supports — and sends them to check
// versions while the real cause, usually an authorisation failure, goes unexamined.
func TestSendAndCollectDoesNotBlameOperatorVersion(t *testing.T) {
	ceremonyFailed := wire.MakeErr(errors.New(string(wire.InitiatorErrorCodeCeremonyFailed)))
	srv := failingOperator(t, http.StatusBadRequest, ceremonyFailed)

	c := &initiator.Initiator{Logger: zap.NewNop(), Client: req.C()}
	op := wire.OperatorCLI{Addr: srv.URL, ID: 11}

	_, err := c.SendAndCollect(op, "resign", []byte("request"))

	require.Error(t, err)
	require.ErrorContains(t, err, "operator 11 failed",
		"the operator that failed must still be named")
	require.ErrorContains(t, err, string(wire.InitiatorErrorCodeCeremonyFailed),
		"the error the operator reported must be passed on as it was")
	require.NotContains(t, err.Error(), "upgrade",
		"a reported ceremony failure is not evidence of a version problem")
	require.NotContains(t, err.Error(), "old version")
}

// TestGetAndCollectStillFlagsUnparseableResponses is the counterpart: on a GET route, a
// body that cannot be decoded as a wire error IS evidence the remote speaks a different
// protocol, and that is the one case where suggesting an upgrade is warranted.
func TestGetAndCollectStillFlagsUnparseableResponses(t *testing.T) {
	srv := failingOperator(t, http.StatusBadRequest, []byte("not an ssz-encoded error"))

	c := &initiator.Initiator{Logger: zap.NewNop(), Client: req.C()}
	op := wire.OperatorCLI{Addr: srv.URL, ID: 11}

	_, err := c.GetAndCollect(op, "health_check")

	require.Error(t, err)
	require.ErrorContains(t, err, "please upgrade",
		"an undecodable response is the case an upgrade hint belongs to")
}
