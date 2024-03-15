package operator

import (
	"crypto/rsa"
	"fmt"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
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
}

// TODO: either do all json or all SSZ
const ErrTooManyRouteRequests = `{"error": "too many requests to /route"}`

// New creates Server structure using operator's RSA private key
func New(key *rsa.PrivateKey, logger *zap.Logger, ver []byte, id uint64) (*Server, error) {
	r := chi.NewRouter()
	operatorPubKey := key.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodeRSAPublicKey(operatorPubKey)
	if err != nil {
		return nil, err
	}
	swtch := NewSwitch(key, logger, ver, pkBytes, id)
	s := &Server{
		Logger: logger,
		Router: r,
		State:  swtch,
	}

	RegisterRoutes(s)
	return s, nil
}

// Start runs a http server to listen for incoming messages at specified port
func (s *Server) Start(port uint16) error {
	srv := &http.Server{Addr: fmt.Sprintf(":%v", port), Handler: s.Router, ReadHeaderTimeout: 10_000 * time.Millisecond}
	s.HttpServer = srv
	err := s.HttpServer.ListenAndServe()
	if err != nil {
		return err
	}
	s.Logger.Info("✅ Server is listening for incoming requests", zap.Uint16("port", port))
	return nil
}
