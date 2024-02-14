package operator

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
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

type KeySign struct {
	ValidatorPK ssvspec_types.ValidatorPK
	SigningRoot []byte
}

// Encode returns a msg encoded bytes or error
func (msg *KeySign) Encode() ([]byte, error) {
	return json.Marshal(msg)
}

// Decode returns error if decoding failed
func (msg *KeySign) Decode(data []byte) error {
	return json.Unmarshal(data, msg)
}

// TODO: either do all json or all SSZ
const ErrTooManyRouteRequests = `{"error": "too many requests to /route"}`

// RegisterRoutes creates routes at operator to process messages incoming from initiator
func RegisterRoutes(s *Server) {
	// Add general rate limiter
	s.Router.Use(rateLimit(s.Logger, generalLimit))
	s.Router.Route("/init", func(r chi.Router) {
		r.Use(rateLimit(s.Logger, routeLimit))
		r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("incoming INIT msg")
			rawdata, err := io.ReadAll(request.Body)
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, failed to read request body, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			signedInitMsg := &wire.SignedTransport{}
			if err := signedInitMsg.UnmarshalSSZ(rawdata); err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, failed to unmarshal SSZ, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}

			// Validate that incoming message is an init message
			if signedInitMsg.Message.Type != wire.InitMessageType {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, received non-init message to init route, err: %v", s.State.OperatorID, errors.New("not init message to init route")), http.StatusBadRequest)
				return
			}
			reqid := signedInitMsg.Message.Identifier
			logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
			logger.Debug("initiating instance with init data")
			b, err := s.State.InitInstance(reqid, signedInitMsg.Message, signedInitMsg.Signature)
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, failed to initialize instance, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			logger.Info("✅ Instance started successfully")

			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		})
	})
	s.Router.Route("/dkg", func(r chi.Router) {
		r.Use(rateLimit(s.Logger, routeLimit))
		r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("received a dkg protocol message")
			rawdata, err := io.ReadAll(request.Body)
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			b, err := s.State.ProcessMessage(rawdata)
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		})
	})
	s.Router.Route("/reshare", func(r chi.Router) {
		r.Use(rateLimit(s.Logger, routeLimit))
		r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("incoming RESHARE msg")
			rawdata, err := io.ReadAll(request.Body)
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			signedReshareMsg := &wire.SignedTransport{}
			if err := signedReshareMsg.UnmarshalSSZ(rawdata); err != nil {
				utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
				return
			}

			// Validate that incoming message is an init message
			if signedReshareMsg.Message.Type != wire.ReshareMessageType {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, err: %v", s.State.OperatorID, errors.New("not init message to init route")), http.StatusBadRequest)
				return
			}
			reqid := signedReshareMsg.Message.Identifier
			logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
			logger.Debug("initiating instance with init data")
			b, err := s.State.InitInstanceReshare(reqid, signedReshareMsg.Message, signedReshareMsg.Signature)
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			logger.Info("✅ Instance started successfully")

			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		})
		s.Router.Route("/health_check", func(r chi.Router) {
			r.Use(rateLimit(s.Logger, routeLimit))
			r.Get("/", func(writer http.ResponseWriter, request *http.Request) {
				b, err := s.State.Pong()
				if err != nil {
					utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
					return
				}
				writer.WriteHeader(http.StatusOK)
				writer.Write(b)
			})
		})
		s.Router.Route("/results", func(r chi.Router) {
			r.Use(rateLimit(s.Logger, routeLimit))
			r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
				rawdata, err := io.ReadAll(request.Body)
				if err != nil {
					utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
					return
				}
				signedResultMsg := &wire.SignedTransport{}
				if err := signedResultMsg.UnmarshalSSZ(rawdata); err != nil {
					utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
					return
				}

				// Validate that incoming message is a result message
				if signedResultMsg.Message.Type != wire.ResultMessageType {
					utils.WriteErrorResponse(s.Logger, writer, errors.New("received wrong message type"), http.StatusBadRequest)
					return
				}
				s.Logger.Debug("received a result message")
				err = s.State.SaveResultData(signedResultMsg)
				if err != nil {
					utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
					return
				}
				writer.WriteHeader(http.StatusOK)
			})
		})
	})
}

// New creates Server structure using operator's RSA private key
func New(key *rsa.PrivateKey, logger *zap.Logger, ver []byte, id uint64) (*Server, error) {
	r := chi.NewRouter()
	operatorPubKey := key.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodePublicKey(operatorPubKey)
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

// Stop closes http server instance
func (s *Server) Stop() error {
	return s.HttpServer.Close()
}

func rateLimit(logger *zap.Logger, limit int) func(http.Handler) http.Handler {
	return httprate.Limit(
		limit,
		timePeriod,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			logger.Debug("rate limit exceeded",
				zap.String("ip", r.RemoteAddr),
				zap.String("path", r.URL.Path))
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(ErrTooManyRouteRequests))
		}),
	)
}
