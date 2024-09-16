package operator

import (
	"encoding/hex"
	"fmt"
	"io"
	"net/http"

	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/pkg/errors"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
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
}

func (s *Server) resignHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming RESIGN msg")
	resignMsg, err := processIncomingRequest(s.Logger, writer, request, wire.ResignMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming resign message", zap.Error(err))
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}

	// hash the message and store it
	resign := &wire.ResignMessage{}
	err = resign.UnmarshalSSZ(resignMsg.Message.Data)
	if err != nil {
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}
	hash := eth_crypto.Keccak256(resignMsg.Message.Data)
	s.State.UnsignedResign[string(hash)] = resign

	s.Logger.Info("✅ Stored unsigned resign message successfully")
}

func (s *Server) reshareHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming RESHARE msg")
	reshareMsg, err := processIncomingRequest(s.Logger, writer, request, wire.ReshareMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming reshare message", zap.Error(err))
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}

	// hash the message and store it
	reshare := &wire.ReshareMessage{}
	err = reshare.UnmarshalSSZ(reshareMsg.Message.Data)
	if err != nil {
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}
	hash := eth_crypto.Keccak256(reshareMsg.Message.Data)
	s.State.UnsignedReshare[string(hash)] = reshare

	s.Logger.Info("✅ Stored unsigned reshare message successfully")
}

func (s *Server) signResignHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming SIGN RESIGN msg")
	signedResignMsg, err := processIncomingRequest(s.Logger, writer, request, wire.SignatureForHashMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming init message", zap.Error(err))
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}

	reqid := signedResignMsg.Message.Identifier
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
	b, err := s.State.HandleInstanceOperation(reqid, signedResignMsg.Message, signedResignMsg.Signer, signedResignMsg.Signature, "resign")
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
}

func (s *Server) signReshareHandler(writer http.ResponseWriter, request *http.Request) {
	s.Logger.Debug("incoming SIGN RESHARE msg")
	signedReshareMsg, err := processIncomingRequest(s.Logger, writer, request, wire.SignatureForHashMessageType, s.State.OperatorID)
	if err != nil {
		s.Logger.Error("Error processing incoming reshare message", zap.Error(err))
		utils.WriteErrorResponse(s.Logger, writer, err, http.StatusBadRequest)
		return
	}

	reqid := signedReshareMsg.Message.Identifier
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqid[:])))
	b, err := s.State.HandleInstanceOperation(reqid, signedReshareMsg.Message, signedReshareMsg.Signer, signedReshareMsg.Signature, "reshare")
	if err != nil {
		utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("operator %d, err: %v", s.State.OperatorID, err), http.StatusBadRequest)
		return
	}
	logger.Info("✅ Reshare instance created successfully")
	writer.WriteHeader(http.StatusOK)
	if _, err := writer.Write(b); err != nil {
		logger.Error("error writing reshare response: " + err.Error())
		return
	}
}
