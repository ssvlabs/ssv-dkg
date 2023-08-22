package test_server

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
	Logger *logrus.Entry
	Router chi.Router
	State  *Switch
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

func RegisterRoutes(s *Server, eve bool) {
	s.Router.Post("/init", func(writer http.ResponseWriter, request *http.Request) {
		s.Logger.Info("Received init msg")
		rawdata, _ := io.ReadAll(request.Body)
		tr := &wire.Transport{}
		if err := tr.UnmarshalSSZ(rawdata); err != nil {
			s.Logger.Errorf("parsing failed, err %v", err)
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		// Validate that incoming message is an init message
		if tr.Type != wire.InitMessageType {
			s.Logger.Errorf("non init message send to init route")
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(errors.New("not init message to init route")))
			return
		}

		reqid := tr.Identifier

		logger := s.Logger.WithField("reqid", hex.EncodeToString(reqid[:]))
		logger.Infof("Initiating instance with init data")
		b, err := s.State.InitInstance(reqid, tr.Data)
		if err != nil {
			logger.Errorf("failed to initiate instance err:%v", err)

			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write(b)
	})

	s.Router.Post("/dkg", func(writer http.ResponseWriter, request *http.Request) {
		s.Logger.Info("Received a dkg protocol message")

		rawdata, err := io.ReadAll(request.Body)
		b, err := s.State.ProcessMessage(rawdata, eve)
		if err != nil {
			writer.WriteHeader(http.StatusBadRequest)
			writer.Write(wire.MakeErr(err))
			return
		}
		writer.WriteHeader(http.StatusOK)
		writer.Write(b)
	})
}

func New(key *rsa.PrivateKey, eve bool) *Server {
	r := chi.NewRouter()
	swtch := NewSwitch(key)
	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &Server{
		Logger: logrus.NewEntry(lg).WithField("comp", "server"),
		Router: r,
		State:  swtch,
	}
	RegisterRoutes(s, eve)
	return s
}

func (s *Server) Start(port uint16) error {
	return http.ListenAndServe(fmt.Sprintf(":%v", port), s.Router)
}
