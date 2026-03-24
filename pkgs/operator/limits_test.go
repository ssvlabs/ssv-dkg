package operator

import (
	"errors"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// maxBytesErrorReader is an io.Reader that immediately returns an
// http.MaxBytesError to simulate a request body that exceeds the allowed size
// without allocating memory proportional to the configured limit.
type maxBytesErrorReader struct{}

func (maxBytesErrorReader) Read(p []byte) (int, error) {
	return 0, &http.MaxBytesError{Limit: maxRequestBodyBytes}
}

type failOnReadBody struct{}

func (failOnReadBody) Read(p []byte) (int, error) {
	return 0, errors.New("body should not have been read")
}

func (failOnReadBody) Close() error {
	return nil
}

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
			body := maxBytesErrorReader{}
			req := httptest.NewRequest(http.MethodPost, "/"+tc.name, body)

			tc.handler(recorder, req)

			require.Equal(t, http.StatusRequestEntityTooLarge, recorder.Code)

			errResponse := &wire.ErrSSZ{}
			err := errResponse.UnmarshalSSZ(recorder.Body.Bytes())
			require.NoError(t, err)
			require.Contains(t, string(errResponse.Error), "request body exceeds limit")
		})
	}
}

func TestReadRequestBodyRejectsOversizedContentLengthWithoutReadingBody(t *testing.T) {
	recorder := httptest.NewRecorder()
	req := httptest.NewRequest(http.MethodPost, "/dkg", io.NopCloser(failOnReadBody{}))
	req.ContentLength = maxRequestBodyBytes + 1

	body, err := readRequestBody(recorder, req, 1)
	require.Nil(t, body)
	require.ErrorIs(t, err, errRequestBodyTooLarge)
	require.Contains(t, err.Error(), "request body exceeds limit")
}

func TestNewHTTPServerSetsLimits(t *testing.T) {
	server := newHTTPServer(3030, http.NewServeMux())

	require.Equal(t, ":3030", server.Addr)
	require.Equal(t, 10*time.Second, server.ReadHeaderTimeout)
	require.Equal(t, maxHeaderBytes, server.MaxHeaderBytes)
	require.Equal(t, 90*time.Second, server.ReadTimeout)
	require.Equal(t, 60*time.Second, server.IdleTimeout)
	require.NotNil(t, server.Handler)
}

func TestNewHTTPServerReadTimeoutAbortsSlowRequestBodies(t *testing.T) {
	handler := http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, err := readRequestBody(writer, request, 1)
		if err != nil {
			http.Error(writer, err.Error(), badRequestStatusCode(err))
			return
		}
		writer.WriteHeader(http.StatusOK)
	})

	server := newHTTPServer(0, handler)
	server.ReadTimeout = 100 * time.Millisecond

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	require.NoError(t, err)

	done := make(chan error, 1)
	go func() {
		done <- server.Serve(listener)
	}()

	defer func() {
		require.NoError(t, server.Close())
		serveErr := <-done
		require.ErrorIs(t, serveErr, http.ErrServerClosed)
	}()

	conn, err := net.Dial("tcp", listener.Addr().String())
	require.NoError(t, err)
	defer func() {
		_ = conn.Close()
	}()

	_, err = conn.Write([]byte("POST / HTTP/1.1\r\nHost: test\r\nContent-Length: 4\r\n\r\na"))
	require.NoError(t, err)

	time.Sleep(250 * time.Millisecond)
	require.NoError(t, conn.SetReadDeadline(time.Now().Add(time.Second)))

	response, err := io.ReadAll(conn)
	require.NoError(t, err)
	require.Contains(t, string(response), "400 Bad Request")
	require.Contains(t, string(response), "failed to read request body")
}
