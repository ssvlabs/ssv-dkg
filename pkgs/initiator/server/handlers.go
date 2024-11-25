package server

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"go.uber.org/zap"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func (s *Server) initHandler(writer http.ResponseWriter, request *http.Request) {
	ctx := context.Background()
	s.Logger.Debug("incoming initial DKG msg")
	rawdata, err := io.ReadAll(request.Body)
	if err != nil {
		s.Logger.Error("failed to read request body", zap.Error(err))
		utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("failed to read request body %w", err), http.StatusBadRequest)
		return
	}
	var initCommandRequest wire.InitJSON
	if err := json.Unmarshal(rawdata, &initCommandRequest); err != nil {
		s.Logger.Error("failed to unmarshal body", zap.Error(err))
		utils.WriteErrorResponse(s.Logger, writer, fmt.Errorf("failed to unmarshal body %w", err), http.StatusBadRequest)
	}
	ethNetwork := e2m_core.NetworkFromString(initCommandRequest.Network)
	if ethNetwork == "" {
		s.Logger.Fatal("😥 Cant recognize eth network")
	}
	initiator.StartInitCeremony(
		ctx,
		s.Logger,
		initCommandRequest.Operators,
		initCommandRequest.OperatorIDs,
		common.HexToAddress(initCommandRequest.Owner),
		common.HexToAddress(initCommandRequest.WithdrawalCredentials),
		initCommandRequest.Nonce,
		initCommandRequest.Amount,
		initCommandRequest.Validators,
		ethNetwork,
		nil,
		true,
		s.OutputPath,
		s.Version,
	)
	writer.WriteHeader(http.StatusOK)
}
