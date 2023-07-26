package server

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
	"io"
	"net/http"
)

type Server struct {
	logger *logrus.Entry
	router chi.Router
	state  *Switch
}

func RegisterRoutes(s *Server) {

	// TODO: create middleware for handling
	// TODO: timeouts for a response creation
	s.router.Post("/init", func(writer http.ResponseWriter, request *http.Request) {
		s.logger.Debug("Got init msg")
		rawdata, _ := io.ReadAll(request.Body)
		s.logger.Debug("parsing init msg")
		tr := &wire.Transport{}
		if err := tr.UnmarshalSSZ(rawdata); err != nil {
			s.logger.Debug("parsing failed, err %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		// Validate that incoming message is an init message
		if tr.Type != wire.InitMessageType {
			s.logger.Debug("non init message send to init route")
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(errors.New("not init message to init route")))
			return
		}

		reqid := tr.Identifier

		// TODO: Validate message signature of the initiator
		logger := s.logger.WithField("reqid", hex.EncodeToString(reqid[:]))

		logger.Infof("Initiating instance with init data")

		b, err := s.state.InitInstance(reqid, tr.Data)
		if err != nil {
			logger.Infof("failed to initiate instance err:%v", err)

			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write(b)
	})

	s.router.Post("/dkg", func(writer http.ResponseWriter, request *http.Request) {
		s.logger.Info("Got dkg message")
		// TODO: Consider validate signature from initiator
		// TODO: error handling
		rawdata, err := io.ReadAll(request.Body)
		b, err := s.state.ProcessMessage(rawdata)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write(b)
	})
}

func New(key *rsa.PrivateKey, opList map[uint64]*rsa.PublicKey) *Server {
	r := chi.NewRouter()
	swtch := NewSwitch(key, opList)
	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &Server{
		logger: logrus.NewEntry(lg).WithField("comp", "server"),
		router: r,
		state:  swtch,
	}
	RegisterRoutes(s)
	return s
}

func (s *Server) Start(port uint16) error {
	return http.ListenAndServe(fmt.Sprintf(":%v", port), s.router)
}
