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
	// TODO: timeouts for a response creation
	s.router.Post("/init", func(writer http.ResponseWriter, request *http.Request) {
		s.logger.Info("Received init msg")
		rawdata, _ := io.ReadAll(request.Body)
		tr := &wire.Transport{}
		if err := tr.UnmarshalSSZ(rawdata); err != nil {
			s.logger.Errorf("parsing failed, err %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		// Validate that incoming message is an init message
		if tr.Type != wire.InitMessageType {
			s.logger.Errorf("non init message send to init route")
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(errors.New("not init message to init route")))
			return
		}

		reqid := tr.Identifier

		// TODO: Consider validating message signature of the initiator
		logger := s.logger.WithField("reqid", hex.EncodeToString(reqid[:]))
		logger.Infof("Initiating instance with init data")
		b, err := s.state.InitInstance(reqid, tr.Data)
		if err != nil {
			logger.Errorf("failed to initiate instance err:%v", err)

			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write(b)
	})

	s.router.Post("/dkg", func(writer http.ResponseWriter, request *http.Request) {
		s.logger.Info("Received a dkg protocol message")
		// TODO: Consider validating signature from initiator
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
