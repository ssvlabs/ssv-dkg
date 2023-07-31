package server

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/go-chi/chi/v5"
	"github.com/sirupsen/logrus"
)

type Server struct {
	logger *logrus.Entry
	router chi.Router
	state  *Switch
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

	s.router.Post("/sign", func(writer http.ResponseWriter, request *http.Request) {
		s.logger.Info("Received request to sign deposit data")
		rawdata, _ := io.ReadAll(request.Body)
		var dataToSign KeySign
		dataToSign.Decode(rawdata)
		return
	})
}

func New(key *rsa.PrivateKey) *Server {
	r := chi.NewRouter()
	swtch := NewSwitch(key)
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
