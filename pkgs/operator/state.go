package operator

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"sort"
	"sync"
	"time"

	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

const MaxInstances = 1024
const MaxInstanceTime = 5 * time.Minute

// InstanceID each new DKG ceremony has a unique random ID that we can identify messages and be able to process them in parallel
type InstanceID [24]byte

// Switch structure to hold many instances created for separate DKG ceremonies
type Switch struct {
	Logger           *zap.Logger
	Mtx              sync.RWMutex
	InstanceInitTime map[InstanceID]time.Time // mapping to store DKG instance creation time
	Instances        map[InstanceID]Instance  // mapping to store DKG instances
	PrivateKey       *rsa.PrivateKey          // operator RSA private key
	Version          []byte
	PubKeyBytes      []byte
	OperatorID       uint64
}

// NewSwitch creates a new Switch
func NewSwitch(pv *rsa.PrivateKey, logger *zap.Logger, ver, pkBytes []byte, id uint64) *Switch {
	return &Switch{
		Logger:           logger,
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		Instances:        make(map[InstanceID]Instance, MaxInstances),
		PrivateKey:       pv,
		Version:          ver,
		PubKeyBytes:      pkBytes,
		OperatorID:       id,
	}
}

// ProcessMessage processes incoming message to /dkg route
func (s *Switch) ProcessMessage(dkgMsg []byte) ([]byte, error) {
	// get instanceID
	st := &wire.MultipleSignedTransports{}
	err := st.UnmarshalSSZ(dkgMsg)
	if err != nil {
		return nil, fmt.Errorf("process message: failed to unmarshal dkg message: %s", err.Error())
	}

	id := InstanceID(st.Identifier)

	s.Mtx.RLock()
	inst, ok := s.Instances[id]
	s.Mtx.RUnlock()

	if !ok {
		return nil, utils.ErrMissingInstance
	}
	return inst.ProcessMessages(st)
}

func (s *Switch) MarshallAndSign(msg wire.SSZMarshaller, msgType wire.TransportType, operatorID uint64, id [24]byte) ([]byte, error) {
	data, err := msg.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	ts := &wire.Transport{
		Type:       msgType,
		Identifier: id,
		Data:       data,
		Version:    s.Version,
	}

	bts, err := ts.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	// Sign message with RSA private key
	sign, err := s.Sign(bts)
	if err != nil {
		return nil, err
	}

	signed := &wire.SignedTransport{
		Message:   ts,
		Signer:    s.PubKeyBytes,
		Signature: sign,
	}

	return signed.MarshalSSZ()
}

func validateInitMessage(init *wire.Init) error {
	if len(init.Owner) != 20 || bytes.Equal(init.Owner[:], make([]byte, 20)) {
		return fmt.Errorf("owner field should be non empty 20 bytes")
	}
	if len(init.Operators) < 4 {
		return fmt.Errorf("wrong old operators len: < 4")
	}
	if len(init.Operators) > 13 {
		return fmt.Errorf("wrong old operators len: > 13")
	}
	if len(init.Operators)%3 != 1 {
		return fmt.Errorf("amount of old operators should be 4,7,10,13")
	}
	sorted := sort.SliceIsSorted(init.Operators, func(p, q int) bool {
		return init.Operators[p].ID < init.Operators[q].ID
	})
	if !sorted {
		return fmt.Errorf("operator not sorted by ID")
	}
	// compute threshold (3f+1)
	threshold := utils.GetThreshold(init.Operators)
	if init.T != uint64(threshold) {
		return fmt.Errorf("threshold field is wrong: expected %d, received %d", threshold, init.T)
	}
	if len(init.WithdrawalCredentials) == 0 || bytes.Equal(init.WithdrawalCredentials, make([]byte, 32)) || bytes.Equal(init.WithdrawalCredentials, make([]byte, 20)) {
		return fmt.Errorf("withdrawal credentials field should be non empty 32 bytes")
	}
	if len(init.Fork) != 4 {
		return fmt.Errorf("fork field should be 4 bytes empty")
	}
	return nil
}

func (s *Switch) Pong() ([]byte, error) {
	pong := &wire.Pong{
		PubKey: s.PubKeyBytes,
	}
	return s.MarshallAndSign(pong, wire.PongMessageType, s.OperatorID, [24]byte{})
}

func (s *Switch) VerifyIncomingMessage(incMsg *wire.SignedTransport) (uint64, error) {
	var initiatorPubKey *rsa.PublicKey
	var ops []*wire.Operator
	var err error
	switch incMsg.Message.Type {
	case wire.PingMessageType:
		ping := &wire.Ping{}
		if err := ping.UnmarshalSSZ(incMsg.Message.Data); err != nil {
			return 0, err
		}
		// Check that incoming message signature is valid
		initiatorPubKey, err = crypto.ParseRSAPublicKey(ping.InitiatorPublicKey)
		if err != nil {
			return 0, err
		}
		ops = ping.Operators
		err = VerifySig(incMsg, initiatorPubKey)
		if err != nil {
			return 0, err
		}
	case wire.ResultMessageType:
		resData := &wire.ResultData{}
		if err := resData.UnmarshalSSZ(incMsg.Message.Data); err != nil {
			return 0, err
		}
		s.Mtx.RLock()
		inst, ok := s.Instances[resData.Identifier]
		s.Mtx.RUnlock()
		if !ok {
			return 0, utils.ErrMissingInstance
		}
		msgBytes, err := incMsg.Message.MarshalSSZ()
		if err != nil {
			return 0, err
		}
		// Check that incoming message signature is valid
		err = inst.VerifyInitiatorMessage(msgBytes, incMsg.Signature)
		if err != nil {
			return 0, err
		}
		ops = resData.Operators
	}
	operatorID, err := GetOperatorID(ops, s.PubKeyBytes)
	if err != nil {
		return 0, err
	}
	return operatorID, nil
}

func SaveResultData(incMsg *wire.SignedTransport, logger *zap.Logger) error {
	resData := &wire.ResultData{}
	err := resData.UnmarshalSSZ(incMsg.Message.Data)
	if err != nil {
		return err
	}
	// Assuming depJson, ksJson, and proofs can be singular instances based on your logic
	var depJson *initiator.DepositDataCLI
	if len(resData.DepositData) != 0 {
		err = json.Unmarshal(resData.DepositData, &depJson)
		if err != nil {
			return err
		}
	}
	var ksJson *initiator.KeyShares
	err = json.Unmarshal(resData.KeysharesData, &ksJson)
	if err != nil {
		return err
	}
	var proof []*initiator.SignedProof
	err = json.Unmarshal(resData.Proofs, &proof)
	if err != nil {
		return err
	}
	// Wrap singular instances in slices for correct parameter passing
	depositDataArr := []*initiator.DepositDataCLI{depJson}
	keySharesArr := []*initiator.KeyShares{ksJson}
	proofsArr := [][]*initiator.SignedProof{proof}
	return cli_utils.WriteResults(depositDataArr, keySharesArr, proofsArr, logger)
}

func GetOperatorID(operators []*wire.Operator, pkBytes []byte) (uint64, error) {
	operatorID := uint64(0)
	for _, op := range operators {
		if bytes.Equal(op.PubKey, pkBytes) {
			operatorID = op.ID
			break
		}
	}
	if operatorID == 0 {
		return 0, fmt.Errorf("wrong operator")
	}
	return operatorID, nil
}
