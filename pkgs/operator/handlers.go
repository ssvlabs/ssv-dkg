package operator

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"fmt"
	"net/http"

	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func sanitizeRequestError(err error) error {
	if errors.Is(err, errRequestBodyTooLarge) {
		return &utils.SensitiveError{Err: err, PresentedErr: "request body too large"}
	}
	return err
}

func sanitizeCeremonyError(err error) error {
	if errors.Is(err, rsa.ErrDecryption) {
		return &utils.SensitiveError{Err: err, PresentedErr: string(wire.InitiatorErrorCodeCeremonyFailed)}
	}
	return err
}

func sanitizeReshareError(err error) error {
	return &utils.SensitiveError{Err: err, PresentedErr: string(wire.InitiatorErrorCodeCeremonyFailed)}
}

func (s *Server) resultsHandler(writer http.ResponseWriter, request *http.Request) {
	signedResultMsg, err := processIncomingRequest(writer, request, wire.ResultMessageType, s.State.OperatorID)
	if err != nil {
		statusCode := badRequestStatusCode(err)
		err = sanitizeRequestError(err)
		utils.WriteErrorResponse(s.Logger, writer, err, statusCode)
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
}

func (s *Server) healthHandler(writer http.ResponseWriter, request *http.Request) {
	b, err := s.State.Pong()
	if err != nil {
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(b); err != nil {
		s.Logger.Error("error sending health_check response", zap.Error(err))
		return
	}
}

func (s *Server) dkgHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("received a dkg protocol message")
	rawdata, err := readRequestBody(writer, request, s.State.OperatorID)
	if err != nil {
		statusCode := badRequestStatusCode(err)
		err = sanitizeRequestError(err)
		utils.WriteErrorResponse(s.Logger, writer, err, statusCode)
		return
	}
	b, err := s.State.ProcessMessage(rawdata)
	if err != nil {
		s.Logger.Error("error processing dkg message", zap.Error(err), zap.Uint64("operator_id", s.State.OperatorID))
		respErr := fmt.Errorf("operator %d, err: %w", s.State.OperatorID, err)
		utils.WriteErrorResponse(s.Logger, writer, sanitizeCeremonyError(respErr), http.StatusBadRequest)
		return
	}
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(b); err != nil {
		s.Logger.Error("error sending response", zap.Error(err))
		return
	}
}

func (s *Server) initHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming INIT msg")
	signedInitMsg, err := processIncomingRequest(writer, request, wire.InitMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming init message", zap.Error(err))
		statusCode := badRequestStatusCode(err)
		err = sanitizeRequestError(err)
		utils.WriteErrorResponse(s.Logger, writer, err, statusCode)
		return
	}
	reqid := signedInitMsg.Message.Identifier
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
	logger.Debug("creating instance with init message data")
	b, err := s.State.InitInstance(reqid, signedInitMsg.Message, signedInitMsg.Signer, signedInitMsg.Signature)
	if err != nil {
		logger.Error("error creating instance", zap.Error(err))
		respErr := fmt.Errorf("operator %d, failed to initialize instance, err: %w", s.State.OperatorID, err)
		utils.WriteErrorResponse(s.Logger, writer, sanitizeCeremonyError(respErr), http.StatusBadRequest)
		return
	}
	logger.Info("✅ Instance started successfully")

	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(b); err != nil {
		s.Logger.Error("error sending init response", zap.Error(err))
		return
	}
}

func (s *Server) signedResignHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming RESIGN msg")
	signedResignMsg, err := processIncomingRequest(writer, request, wire.SignedResignMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming resign message", zap.Error(err))
		statusCode := badRequestStatusCode(err)
		err = sanitizeRequestError(err)
		utils.WriteErrorResponse(s.Logger, writer, err, statusCode)
		return
	}

	reqid := signedResignMsg.Message.Identifier
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
	b, err := s.State.HandleInstanceOperation(reqid, signedResignMsg.Message, signedResignMsg.Signer, signedResignMsg.Signature, "resign")
	if err != nil {
		logger.Error("error resigning instance", zap.Error(err))
		respErr := fmt.Errorf("operator %d, failed to resign, err: %w", s.State.OperatorID, err)
		utils.WriteErrorResponse(s.Logger, writer, sanitizeCeremonyError(respErr), http.StatusBadRequest)
		return
	}
	logger.Info("✅ resigned data successfully")
	writer.WriteHeader(http.StatusOK)
	flattenedResp := utils.FlattenReponseMsgs(b)
	if _, err := writer.Write(flattenedResp); err != nil {
		logger.Error("error writing resign response: " + err.Error())
		return
	}
}

func (s *Server) signedReshareHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming RESHARE msg")
	signedReshareMsg, err := processIncomingRequest(writer, request, wire.SignedReshareMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming reshare message", zap.Error(err))
		statusCode := badRequestStatusCode(err)
		err = sanitizeRequestError(err)
		utils.WriteErrorResponse(s.Logger, writer, err, statusCode)
		return
	}

	reqid := signedReshareMsg.Message.Identifier
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
	b, err := s.State.HandleInstanceOperation(reqid, signedReshareMsg.Message, signedReshareMsg.Signer, signedReshareMsg.Signature, "reshare")
	if err != nil {
		logger.Error("error resharing instance", zap.Error(err))
		respErr := fmt.Errorf("operator %d, err: %w", s.State.OperatorID, err)
		utils.WriteErrorResponse(s.Logger, writer, sanitizeReshareError(respErr), http.StatusBadRequest)
		return
	}
	logger.Info("✅ Reshare instance created successfully")
	writer.WriteHeader(http.StatusOK)
	flattenedResp := utils.FlattenReponseMsgs(b)
	if _, err := writer.Write(flattenedResp); err != nil {
		logger.Error("error writing reshare response: " + err.Error())
		return
	}
}
