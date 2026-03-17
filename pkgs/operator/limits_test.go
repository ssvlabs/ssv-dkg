package operator

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
)

func TestHandlersRejectOversizedRequestBody(t *testing.T) {
	server := &Server{
		Logger: zap.NewNop(),
		State:  &Switch{OperatorID: 1},
	}

	testCases := []struct {
		name    string
		handler http.HandlerFunc
	}{
		{name: "init", handler: server.initHandler},
		{name: "dkg", handler: server.dkgHandler},
		{name: "results", handler: server.resultsHandler},
		{name: "resign", handler: server.signedResignHandler},
		{name: "reshare", handler: server.signedReshareHandler},
	}

	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			recorder := httptest.NewRecorder()
			req := httptest.NewRequest(http.MethodPost, "/"+tc.name, bytes.NewReader(make([]byte, maxRequestBodyBytes+1)))

			tc.handler(recorder, req)

			require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)
			require.Contains(t, recorder.Body.String(), "request body exceeds limit")
		})
	}
}

func TestNewHTTPServerSetsLimits(t *testing.T) {
	server := newHTTPServer(3030, http.NewServeMux())

	require.Equal(t, ":3030", server.Addr)
	require.Equal(t, 10*time.Second, server.ReadHeaderTimeout)
	require.Equal(t, maxHeaderBytes, server.MaxHeaderBytes)
}
