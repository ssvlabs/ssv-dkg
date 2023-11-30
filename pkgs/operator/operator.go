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

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/bloxapp/ssv/storage/kv"
)

// Server structure for operator to store http server and DKG ceremony instances
type Server struct {
	Logger     *zap.Logger  // logger
	HttpServer *http.Server //http server
	Router     chi.Router   // http router
	State      *Switch      // structure to store instances of DKG ceremonies
	DB         *kv.BadgerDB
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
const ErrTooManyOperatorRequests = `{"error": "too many requests to operator"}`
const ErrTooManyDKGRequests = `{"error": "too many requests to initiate DKG"}`

// RegisterRoutes creates routes at operator to process messages incoming from initiator
func RegisterRoutes(s *Server) {
	// Add general rate limiter
	s.Router.Use(httprate.Limit(
		5000,
		1*time.Minute,
		httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Content-Type", "application/json")
			w.WriteHeader(http.StatusTooManyRequests)
			w.Write([]byte(ErrTooManyOperatorRequests))
		}),
	))
	s.Router.Route("/init", func(r chi.Router) {
		r.Use(httprate.Limit(
			1000,
			time.Minute,
			httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(ErrTooManyDKGRequests))
			}),
		))
		r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("incoming INIT msg")
			rawdata, _ := io.ReadAll(request.Body)
			signedInitMsg := &wire.SignedTransport{}
			if err := signedInitMsg.UnmarshalSSZ(rawdata); err != nil {
				s.Logger.Error("parsing failed: ", zap.Error(err))
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(err))
				return
			}

			// Validate that incoming message is an init message
			if signedInitMsg.Message.Type != wire.InitMessageType {
				s.Logger.Error("received bad msg non init message sent to init route")
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(errors.New("not init message to init route")))
				return
			}
			reqid := signedInitMsg.Message.Identifier
			logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
			logger.Debug("initiating instance with init data")
			b, err := s.State.InitInstance(reqid, signedInitMsg.Message, signedInitMsg.Signature)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to initiate instance err:%v", err))

				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(err))
				return
			}
			logger.Info("✅ Instance started successfully")

			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		})
	})
	s.Router.Route("/dkg", func(r chi.Router) {
		r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("received a dkg protocol message")
			rawdata, err := io.ReadAll(request.Body)
			if err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(err))
				return
			}
			b, err := s.State.ProcessMessage(rawdata)
			if err != nil {
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(err))
				return
			}
			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		})
	})
	s.Router.Route("/reshare", func(r chi.Router) {
		r.Use(httprate.Limit(
			1000,
			time.Minute,
			httprate.WithLimitHandler(func(w http.ResponseWriter, r *http.Request) {
				w.Header().Set("Content-Type", "application/json")
				w.WriteHeader(http.StatusTooManyRequests)
				w.Write([]byte(ErrTooManyDKGRequests))
			}),
		))
		r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
			s.Logger.Debug("incoming RESHARE msg")
			rawdata, _ := io.ReadAll(request.Body)
			signedReshareMsg := &wire.SignedTransport{}
			if err := signedReshareMsg.UnmarshalSSZ(rawdata); err != nil {
				s.Logger.Error("parsing failed: ", zap.Error(err))
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(err))
				return
			}

			// Validate that incoming message is an init message
			if signedReshareMsg.Message.Type != wire.ReshareMessageType {
				s.Logger.Error("received bad msg non init message sent to init route")
				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(errors.New("not init message to init route")))
				return
			}
			reqid := signedReshareMsg.Message.Identifier
			logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
			logger.Debug("initiating instance with init data")
			b, err := s.State.InitInstanceReshare(reqid, signedReshareMsg.Message, signedReshareMsg.Signature)
			if err != nil {
				logger.Error(fmt.Sprintf("failed to initiate instance err:%v", err))

				writer.WriteHeader(http.StatusBadRequest)
				writer.Write(wire.MakeErr(err))
				return
			}
			logger.Info("✅ Instance started successfully")

			writer.WriteHeader(http.StatusOK)
			writer.Write(b)
		})
		s.Router.Route("/health_check", func(r chi.Router) {
			r.Post("/", func(writer http.ResponseWriter, request *http.Request) {
				rawdata, _ := io.ReadAll(request.Body)
				signedPintMsg := &wire.SignedTransport{}
				if err := signedPintMsg.UnmarshalSSZ(rawdata); err != nil {
					s.Logger.Error("parsing failed: ", zap.Error(err))
					writer.WriteHeader(http.StatusBadRequest)
					writer.Write(wire.MakeErr(err))
					return
				}
	
				// Validate that incoming message is an ping message
				if signedPintMsg.Message.Type != wire.PingMessageType {
					s.Logger.Error("received bad msg non ping message sent to ping route")
					writer.WriteHeader(http.StatusBadRequest)
					writer.Write(wire.MakeErr(errors.New("not ping message to ping route")))
					return
				}
				s.Logger.Debug("received a health check message")
				b, err := s.State.Pong(signedPintMsg.Message, signedPintMsg.Signature)
				if err != nil {
					s.Logger.Error(fmt.Sprintf("failed to create pong message:%v", err))
					writer.WriteHeader(http.StatusBadRequest)
					writer.Write(wire.MakeErr(err))
					return
				}
				writer.WriteHeader(http.StatusOK)
				writer.Write(b)
			})
		})
	})
}

// New creates Server structure using operator's RSA private key
func New(key *rsa.PrivateKey, logger *zap.Logger, dbOptions basedb.Options) *Server {
	r := chi.NewRouter()
	db, err := setupDB(logger, dbOptions)
	// todo: handle error
	if err != nil {
		panic(err)
	}
	swtch := NewSwitch(key, logger, db)
	s := &Server{
		Logger: logger,
		Router: r,
		State:  swtch,
		DB:     db,
	}
	RegisterRoutes(s)
	return s
}

// Start runs a http server to listen for incoming messages at specified port
func (s *Server) Start(port uint16) error {
	srv := &http.Server{Addr: fmt.Sprintf(":%v", port), Handler: s.Router}
	s.HttpServer = srv
	err := s.HttpServer.ListenAndServe()
	if err != nil {
		return err
	}
	s.Logger.Info("✅ Server is listening for incoming requests", zap.Uint16("port", port))
	return nil
}

func setupDB(logger *zap.Logger, dbOptions basedb.Options) (*kv.BadgerDB, error) {
	db, err := kv.New(logger, dbOptions)
	if err != nil {
		return nil, errors.Wrap(err, "failed to open db")
	}
	return db, nil
}

// Stop closes http server instance
func (s *Server) Stop() error {
	return s.HttpServer.Close()
}
