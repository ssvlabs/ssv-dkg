package operator

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// request limits
const (
	generalLimit          = 5000
	initRouteLimit        = 200
	resignRouteLimit      = 200
	reshareRouteLimit     = 200
	dkgRouteLimit         = 500
	healthCheckRouteLimit = 500
	resultsRouteLimit     = 500
	// maxRequestBodyBytes is set to accommodate the worst-case `/dkg` SSZ payload:
	// up to 13 SignedTransports with 8 MiB Transport.Data each (~104 MiB total),
	// plus SSZ container overhead and fixed fields (with an extra 1 MiB margin).
	maxRequestBodyBytes   = 105 << 20
	maxHeaderBytes        = 1 << 20
	timePeriod            = time.Minute
)

// Server structure for operator to store http server and DKG ceremony instances
type Server struct {
	Logger     *zap.Logger  // logger
	HttpServer *http.Server // http server
	Router     chi.Router   // http router
	State      *Switch      // structure to store instances of DKG ceremonies
	OutputPath string
}

// TODO: either do all json or all SSZ
const ErrTooManyRouteRequests = `{"error": "too many requests to /route"}`

type requestBodyTooLargeError struct {
	limit int64
}

func (e *requestBodyTooLargeError) Error() string {
	return fmt.Sprintf("request body exceeds limit of %d bytes", e.limit)
}

// New creates Server structure using operator's RSA private key
func New(key *rsa.PrivateKey, logger *zap.Logger, ver []byte, id uint64, outputPath, ethEndpointURL string) (*Server, error) {
	r := chi.NewRouter()
	operatorPubKey := key.Public().(*rsa.PublicKey)
	pkBytes, err := spec_crypto.EncodeRSAPublicKey(operatorPubKey)
	if err != nil {
		return nil, err
	}
	ethBackend, err := ethclient.Dial(ethEndpointURL)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to Ethereum backend, err: %w", err)
	}
	swtch := NewSwitch(key, logger, ver, pkBytes, id, ethBackend)
	s := &Server{
		Logger:     logger,
		Router:     r,
		State:      swtch,
		OutputPath: outputPath,
	}
	RegisterRoutes(s)
	return s, nil
}

// Start runs a http server to listen for incoming messages at specified port
func (s *Server) Start(port uint16, cert, key string) error {
	srv := newHTTPServer(port, s.Router)
	s.HttpServer = srv
	s.Logger.Info("✅ Server is starting and listening for incoming requests", zap.Uint16("port", port))
	err := s.HttpServer.ListenAndServeTLS(cert, key)
	if err != nil {
		if errors.Is(err, http.ErrServerClosed) {
			s.Logger.Info("HTTP server shut down gracefully", zap.Uint16("port", port))
			return nil
		}
		return err
	}
	return nil
}

func newHTTPServer(port uint16, handler http.Handler) *http.Server {
	return &http.Server{
		Addr:              fmt.Sprintf(":%v", port),
		Handler:           handler,
		ReadHeaderTimeout: 10 * time.Second,
		ReadTimeout:       10 * time.Minute,
		WriteTimeout:      30 * time.Second,
		IdleTimeout:       60 * time.Second,
		MaxHeaderBytes:    maxHeaderBytes,
	}
}

func readRequestBody(writer http.ResponseWriter, request *http.Request, operatorID uint64) ([]byte, error) {
	request.Body = http.MaxBytesReader(writer, request.Body, maxRequestBodyBytes)
	rawdata, err := io.ReadAll(request.Body)
	if err != nil {
		var maxBytesErr *http.MaxBytesError
		if errors.As(err, &maxBytesErr) {
			return nil, fmt.Errorf("operator %d, %w", operatorID, &requestBodyTooLargeError{limit: maxRequestBodyBytes})
		}
		return nil, fmt.Errorf("operator %d, failed to read request body, err: %w", operatorID, err)
	}
	return rawdata, nil
}

func requestReadStatusCode(err error) int {
	var bodyTooLargeErr *requestBodyTooLargeError
	if errors.As(err, &bodyTooLargeErr) {
		return http.StatusRequestEntityTooLarge
	}
	return http.StatusBadRequest
}

func processIncomingRequest(writer http.ResponseWriter, request *http.Request, reqMessageType wire.TransportType, operatorID uint64) (*wire.SignedTransport, error) {
	rawdata, err := readRequestBody(writer, request, operatorID)
	if err != nil {
		return nil, err
	}
	signedMsg := &wire.SignedTransport{}
	if err := signedMsg.UnmarshalSSZ(rawdata); err != nil {
		return nil, fmt.Errorf("operator %d, failed to unmarshal SSZ, err: probably an upgrade to latest version needed: %w", operatorID, err)
	}
	// Validate that incoming message has requested type
	if signedMsg.Message.Type != reqMessageType {
		return nil, fmt.Errorf("operator %d, received wrong message type: want %s, got: %s", operatorID, reqMessageType, signedMsg.Message.Type)
	}
	return signedMsg, nil
}
