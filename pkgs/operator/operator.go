package operator

import (
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
	"time"

	"github.com/go-chi/chi/v5"
	"github.com/go-chi/httprate"
	"github.com/pkg/errors"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
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

// RegisterRoutes creates routes at operator to process messages incoming from initiator
func RegisterRoutes(s *Server) {
	// Add general rate limiter
	s.Router.Use(rateLimit(s.Logger, generalLimit))

	s.Router.With(rateLimit(s.Logger, routeLimit)).
		Post("/init", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("incoming INIT msg")
			signedInitMsg, err := processIncomingRequest(s.Logger, writer, request, wire.InitMessageType, s.State.OperatorID)
			if err != nil {
				s.Logger.Error("Error processing incoming init message", zap.Error(err))
				utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
				return
			}
			reqid := signedInitMsg.Message.Identifier
			logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
			logger.Debug("creating instance with init message data")
			b, err := s.State.InitInstance(reqid, signedInitMsg.Message, signedInitMsg.Signer, signedInitMsg.Signature)
			if err != nil {
				s.Logger.Error("Error creating instance", zap.Error(err))
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, failed to initialize instance, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			logger.Info("✅ Instance started successfully")

			writer.WriteHeader(http.StatusOK)
			if _, err := writer.Write(b); err != nil {
				logger.Error("error writing init response: " + err.Error())
				return
			}
		})
	s.Router.With(rateLimit(s.Logger, routeLimit)).
		Post("/resign", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("incoming RESIGN msg")
			signedResignMsg, err := processIncomingRequest(s.Logger, writer, request, wire.ResignMessageType, s.State.OperatorID)
			if err != nil {
				s.Logger.Error("Error processing incoming init message", zap.Error(err))
				utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
				return
			}
			reqid := signedResignMsg.Message.Identifier
			logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
			b, err := s.State.ResignInstance(reqid, signedResignMsg.Message, signedResignMsg.Signer, signedResignMsg.Signature)
			if err != nil {
				s.Logger.Error("Error resigning instance", zap.Error(err))
				utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, failed to resign, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
				return
			}
			logger.Info("✅ resigned data successfully")
			writer.WriteHeader(http.StatusOK)
			if _, err := writer.Write(b); err != nil {
				logger.Error("error writing resign response: " + err.Error())
				return
			}
		})
	s.Router.With(rateLimit(s.Logger, routeLimit)).
		Post("/dkg", func(writer http.ResponseWriter, request *http.Request) {
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
			if _, err := writer.Write(b); err != nil {
				s.Logger.Error("error writing dkg response: " + err.Error())
				return
			}
		})

	s.Router.With(rateLimit(s.Logger, routeLimit)).
		Get("/health_check", func(writer http.ResponseWriter, request *http.Request) {
			b, err := s.State.Pong()
			if err != nil {
				utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusOK)
			if _, err := writer.Write(b); err != nil {
				s.Logger.Error("error writing health_check response: " + err.Error())
				return
			}
		})

	s.Router.With(rateLimit(s.Logger, routeLimit)).
		Post("/results", func(writer http.ResponseWriter, request *http.Request) {
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
			err = s.State.SaveResultData(signedResultMsg, s.OutputPath)
			if err != nil {
				err := &utils.SensitiveError{Err: err, PresentedErr: "failed to write results"}
				utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
				return
			}
			writer.WriteHeader(http.StatusOK)
		})
}

// New creates Server structure using operator's RSA private key
func New(key *rsa.PrivateKey, logger *zap.Logger, ver []byte, id uint64, outputPath string) (*Server, error) {
	r := chi.NewRouter()
	operatorPubKey := key.Public().(*rsa.PublicKey)
	pkBytes, err := spec_crypto.EncodeRSAPublicKey(operatorPubKey)
	if err != nil {
		return nil, err
	}
	swtch := NewSwitch(key, logger, ver, pkBytes, id)
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
			_, err := w.Write([]byte(ErrTooManyRouteRequests))
			if err != nil {
				logger.Error("error writing rate limit response: " + err.Error())
			}
		}),
	)
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
		return nil, fmt.Errorf("operator %d, received non-init message to init route, err: %v", operatorID, errors.New("not init message to init route"))
	}
	return signedMsg, nil
}

func getIDsFromOperatorsArray(ops []*spec.Operator) []uint64 {
	ids := make([]uint64, 0)
	for _, op := range ops {
		ids = append(ids, op.ID)
	}
	return ids
}
