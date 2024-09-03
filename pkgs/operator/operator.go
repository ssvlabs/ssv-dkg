package operator

import (
	"crypto/rsa"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
)

// request limits
const (
	generalLimit = 5000
	routeLimit   = 500
	timePeriod   = time.Minute
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

// New creates Server structure using operator's RSA private key
func New(key *rsa.PrivateKey, logger *zap.Logger, ver []byte, id uint64, outputPath string, ethEndpointURL string) (*Server, error) {
	r := chi.NewRouter()
	operatorPubKey := key.Public().(*rsa.PublicKey)
	pkBytes, err := spec_crypto.EncodeRSAPublicKey(operatorPubKey)
	if err != nil {
		return nil, err
	}
	ethBackend, err := ethclient.Dial(ethEndpointURL)
	if err != nil {
		return nil, err
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
	srv := &http.Server{Addr: fmt.Sprintf(":%v", port), Handler: s.Router, ReadHeaderTimeout: 10_000 * time.Millisecond}
	s.HttpServer = srv
	err := s.HttpServer.ListenAndServeTLS(cert, key)
	if err != nil {
		return err
	}
	s.Logger.Info("✅ Server is listening for incoming requests", zap.Uint16("port", port))
	return nil
}

func processIncomingRequest(logger *zap.Logger, writer http.ResponseWriter, request *http.Request, reqMessageType wire.TransportType, operatorID uint64) (*wire.SignedTransport, error) {
	rawdata, err := io.ReadAll(request.Body)
	if err != nil {
		return nil, fmt.Errorf("operator %d, failed to read request body, err: %v", operatorID, err)
	}
	signedMsg := &wire.SignedTransport{}
	if err := signedMsg.UnmarshalSSZ(rawdata); err != nil {
		return nil, fmt.Errorf("operator %d, failed to unmarshal SSZ, err: %v", operatorID, err)
	}
	// Validate that incoming message has requested type
	if signedMsg.Message.Type != reqMessageType {
		return nil, fmt.Errorf("operator %d, received wrong message typec", operatorID)
	}
	return signedMsg, nil
}
