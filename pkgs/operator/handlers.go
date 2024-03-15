package operator

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/pkg/errors"
	"go.uber.org/zap"
)

func (s *Server) resultsHandler(writer http.ResponseWriter, request *http.Request) {
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
	_, err = s.State.VerifyIncomingMessage(signedResultMsg)
	if err != nil {
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}
	err = SaveResultData(signedResultMsg, s.Logger)
	if err != nil {
		err := &utils.SensitiveError{Err: err, PresentedErr: "failed to write results"}
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
}

func (s *Server) healthHandler(writer http.ResponseWriter, request *http.Request) {
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
}

func (s *Server) dkgHandler(writer http.ResponseWriter, request *http.Request) {
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
}

func (s *Server) initHandler(writer http.ResponseWriter, request *http.Request) {
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
	b, err := s.State.InitInstance(reqid, signedInitMsg.Message, signedInitMsg.Signer, signedInitMsg.Signature)
	if err != nil {
		utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, failed to initialize instance, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
		return
	}
	logger.Info("✅ Instance started successfully")

	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(b); err != nil {
		logger.Error("error writing init response: " + err.Error())
		return
	}
}
