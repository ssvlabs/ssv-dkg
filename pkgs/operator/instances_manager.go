package operator

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"time"

	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/dkg"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// CreateInstance creates a LocalOwner instance with the DKG ceremony ID, that we can identify it later. Initiator public key identifies an initiator for
// new instance. There cant be two instances with the same ID, but one initiator can start several DKG ceremonies.
func (s *Switch) CreateInstance(reqID [24]byte, operators []*spec.Operator, message interface{}, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {
	operatorID, err := spec.OperatorIDByPubKey(operators, s.PubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	// sanity check of operator ID
	if s.OperatorID != operatorID {
		return nil, nil, fmt.Errorf("wrong operator ID: want %d, got %d", s.OperatorID, operatorID)
	}
	bchan := make(chan []byte, 1)
	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}
	opts := dkg.OwnerOpts{
		Logger:             s.Logger.With(zap.String("instance", hex.EncodeToString(reqID[:]))),
		BroadcastF:         broadcast,
		Signer:             crypto.RSASigner(s.PrivateKey),
		EncryptFunc:        s.Encrypt,
		DecryptFunc:        s.Decrypt,
		Suite:              kyber_bls12381.NewBLS12381Suite(),
		ID:                 operatorID,
		InitiatorPublicKey: initiatorPublicKey,
		OperatorSecretKey:  s.PrivateKey,
		Version:            s.Version,
	}
	owner := dkg.New(&opts)
	var resp *wire.Transport
	// wait for exchange msg
	switch msg := message.(type) {
	case *spec.Init:
		resp, err = owner.Init(reqID, msg)
		if err != nil {
			return nil, nil, err
		}
	case *wire.ResignMessage:
		resp, err = owner.Resign(reqID, msg)
		if err != nil {
			return nil, nil, err
		}
	case *wire.ReshareMessage:
		commits, share, err := s.getPublicCommitsAndSecretShare(msg)
		if err != nil {
			return nil, nil, err
		}
		owner.SecretShare = share
		resp, err = owner.Reshare(reqID, msg.Reshare, commits)
		if err != nil {
			return nil, nil, err
		}
	default:
		return nil, nil, fmt.Errorf("cant determine the ceremony message type")
	}
	if err := owner.Broadcast(resp); err != nil {
		return nil, nil, err
	}
	res := <-bchan
	return &instWrapper{owner, initiatorPublicKey, bchan}, res, nil
}

// InitInstance creates a LocalOwner instance and DKG public key message (Exchange)
func (s *Switch) InitInstance(reqID [24]byte, initMsg *wire.Transport, initiatorPub, initiatorSignature []byte) ([]byte, error) {
	if !bytes.Equal(initMsg.Version, s.Version) {
		return nil, fmt.Errorf("wrong version: remote %s local %s", initMsg.Version, s.Version)
	}
	s.Logger.Info("🚀 Initializing Init instance")
	init := &spec.Init{}
	if err := init.UnmarshalSSZ(initMsg.Data); err != nil {
		return nil, fmt.Errorf("failed to ssz unmarshal message: probably an upgrade to latest version needed: %w", err)
	}
	if err := spec.ValidateInitMessage(init); err != nil {
		return nil, err
	}
	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("init: failed parse initiator public key: %w", err)
	}
	marshalledWireMsg, err := initMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("init: failed to marshal transport message: %w", err)
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("init: initiator signature isn't valid: %w", err)
	}
	s.Logger.Info("✅ init message signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))
	if err := s.validateInstances(reqID); err != nil {
		return nil, err
	}
	inst, resp, err := s.CreateInstance(reqID, init.Operators, init, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("init: failed to create instance: %w", err)
	}
	s.Mtx.Lock()
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

// cleanInstances removes all instances at Switch
func (s *Switch) cleanInstances() int {
	count := 0
	for id, instime := range s.InstanceInitTime {
		if time.Now().After(instime.Add(MaxInstanceTime)) {
			delete(s.Instances, id)
			delete(s.InstanceInitTime, id)
			count++
		}
	}
	return count
}

// HandleInstanceOperation handles both Resign and Reshare operations.
func (s *Switch) HandleInstanceOperation(reqID [24]byte, transportMsg *wire.Transport, initiatorPub, initiatorSignature []byte, operationType string) ([][]byte, error) {
	if !bytes.Equal(transportMsg.Version, s.Version) {
		return nil, fmt.Errorf("wrong version: remote %s local %s", transportMsg.Version, s.Version)
	}

	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse initiator public key: %w", operationType, err)
	}
	marshalledWireMsg, err := transportMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal transport message: %w", operationType, err)
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("%s: initiator signature isn't valid: %w", operationType, err)
	}

	s.Logger.Info(fmt.Sprintf("🚀 Handling %s operation", operationType))

	var allOps []*spec.Operator

	switch operationType {
	case "resign":
		signedResign := &wire.SignedResign{}
		if err := signedResign.UnmarshalSSZ(transportMsg.Data); err != nil {
			return nil, fmt.Errorf("failed to ssz unmarshal message: probably an upgrade to latest version needed: %w", err)
		}
		allOps = signedResign.Messages[0].Operators
		hexString, err := utils.GetMessageString(signedResign.Messages)
		if err != nil {
			return nil, err
		}
		s.Logger.Info("Incoming resign request fields",
			zap.String("network", hex.EncodeToString(signedResign.Messages[0].Resign.Fork[:])),
			zap.String("withdrawal", hex.EncodeToString(signedResign.Messages[0].Resign.WithdrawalCredentials)),
			zap.String("owner", hex.EncodeToString(signedResign.Messages[0].Resign.Owner[:])),
			zap.String("resign message hash", hexString),
			zap.String("EIP1271 owner signature", hex.EncodeToString(signedResign.Signature)))

		// verify EIP1271 signature
		hash, err := utils.GetMessageHash(signedResign.Messages)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to create instance: %w", operationType, err)
		}
		if err := spec_crypto.VerifySignedMessageByOwner(
			s.EthClient,
			signedResign.Messages[0].Proofs[0].Proof.Owner,
			hash,
			signedResign.Signature,
		); err != nil {
			return nil, fmt.Errorf("failed to verify signed message by owner: %w", err)
		}

		s.Logger.Info(fmt.Sprintf("✅ %s eip1271 owner signature is successfully verified", operationType), zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))

		resps := [][]byte{}
		// Run all resign/reshare ceremonies
		for _, instance := range signedResign.Messages {
			resp, err := s.runInstance(reqID, instance, allOps, initiatorPubKey, operationType)
			if err != nil {
				return nil, fmt.Errorf("%s: failed to run instance: %w", operationType, err)
			}
			resps = append(resps, resp)
		}

		return resps, nil

	case "reshare":
		signedReshare := &wire.SignedReshare{}
		if err := signedReshare.UnmarshalSSZ(transportMsg.Data); err != nil {
			return nil, fmt.Errorf("failed to ssz unmarshal message: probably an upgrade to latest version needed: %w", err)
		}
		if len(signedReshare.Messages) == 0 {
			return nil, fmt.Errorf("%s: no reshare messages", operationType)
		}
		allOps = append(allOps, signedReshare.Messages[0].Reshare.OldOperators...)
		allOps = append(allOps, signedReshare.Messages[0].Reshare.NewOperators...)
		hexString, err := utils.GetMessageString(signedReshare.Messages)
		if err != nil {
			return nil, err
		}
		s.Logger.Info("Incoming reshare request fields",
			zap.Any("Old operator IDs", utils.GetOpIDs(signedReshare.Messages[0].Reshare.OldOperators)),
			zap.Any("New operator IDs", utils.GetOpIDs(signedReshare.Messages[0].Reshare.NewOperators)),
			zap.String("network", hex.EncodeToString(signedReshare.Messages[0].Reshare.Fork[:])),
			zap.String("withdrawal", hex.EncodeToString(signedReshare.Messages[0].Reshare.WithdrawalCredentials)),
			zap.String("owner", hex.EncodeToString(signedReshare.Messages[0].Reshare.Owner[:])),
			zap.String("reshare message hash", hexString),
			zap.String("EIP1271 owner signature", hex.EncodeToString(signedReshare.Signature)))

		// verify EIP1271 signature
		hash, err := utils.GetMessageHash(signedReshare.Messages)
		if err != nil {
			return nil, fmt.Errorf("%s: failed to create instance: %w", operationType, err)
		}
		if err := spec_crypto.VerifySignedMessageByOwner(
			s.EthClient,
			signedReshare.Messages[0].Proofs[0].Proof.Owner,
			hash,
			signedReshare.Signature,
		); err != nil {
			return nil, fmt.Errorf("failed to verify signed message by owner: %w", err)
		}

		s.Logger.Info(fmt.Sprintf("✅ %s eip1271 owner signature is successfully verified", operationType), zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))

		resps := [][]byte{}
		// Run all resign/reshare ceremonies
		for _, instance := range signedReshare.Messages {
			resp, err := s.runInstance(reqID, instance, allOps, initiatorPubKey, operationType)
			if err != nil {
				return nil, fmt.Errorf("%s: failed to run instance: %w", operationType, err)
			}
			resps = append(resps, resp)
		}

		return resps, nil

	default:
		return nil, fmt.Errorf("unknown operation type: %s", operationType)
	}
}

// Helper functions to abstract out common behavior
func (s *Switch) validateInstances(reqID InstanceID) error {
	s.Mtx.Lock()
	l := len(s.Instances)
	if l >= MaxInstances {
		cleaned := s.cleanInstances()
		if l-cleaned >= MaxInstances {
			s.Mtx.Unlock()
			return utils.ErrMaxInstances
		}
	}
	_, ok := s.Instances[reqID]
	if ok {
		tm := s.InstanceInitTime[reqID]
		if time.Now().Before(tm.Add(MaxInstanceTime)) {
			s.Mtx.Unlock()
			return utils.ErrAlreadyExists
		}
		delete(s.Instances, reqID)
		delete(s.InstanceInitTime, reqID)
	}
	s.Mtx.Unlock()
	return nil
}

func (s *Switch) runInstance(reqID [24]byte, instance interface{}, allOps []*spec.Operator, initiatorPubKey *rsa.PublicKey, operationType string) ([]byte, error) {
	instanceID, err := utils.GetReqIDfromMsg(instance, reqID)
	if err != nil {
		return nil, err
	}
	if err := s.validateInstances(instanceID); err != nil {
		return nil, err
	}

	inst, resp, err := s.CreateInstance(instanceID, allOps, instance, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create instance: %w", operationType, err)
	}

	s.Mtx.Lock()
	s.Instances[instanceID] = inst
	s.InstanceInitTime[instanceID] = time.Now()
	s.Mtx.Unlock()

	return resp, nil
}
