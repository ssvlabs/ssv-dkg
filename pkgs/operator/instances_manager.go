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
		return nil, fmt.Errorf("init: failed to unmarshal init message: %s", err.Error())
	}
	if err := spec.ValidateInitMessage(init); err != nil {
		return nil, err
	}
	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("init: failed parse initiator public key: %s", err.Error())
	}
	marshalledWireMsg, err := initMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("init: failed to marshal transport message: %s", err.Error())
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("init: initiator signature isn't valid: %s", err.Error())
	}
	s.Logger.Info("✅ init message signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))
	if err := s.validateInstances(reqID); err != nil {
		return nil, err
	}
	inst, resp, err := s.CreateInstance(reqID, init.Operators, init, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("init: failed to create instance: %s", err.Error())
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
func (s *Switch) HandleInstanceOperation(reqID [24]byte, transportMsg *wire.Transport, initiatorPub, initiatorSignature []byte, operationType string) ([]byte, error) {
	if !bytes.Equal(transportMsg.Version, s.Version) {
		return nil, fmt.Errorf("wrong version: remote %s local %s", transportMsg.Version, s.Version)
	}

	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse initiator public key: %s", operationType, err.Error())
	}
	marshalledWireMsg, err := transportMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal transport message: %s", operationType, err.Error())
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("%s: initiator signature isn't valid: %s", operationType, err.Error())
	}

	s.Logger.Info(fmt.Sprintf("🚀 Handling %s operation", operationType))

	var (
		instanceMessage interface{}
		allOps          []*spec.Operator
	)

	sig := &wire.SignatureForHash{}
	if err := sig.UnmarshalSSZ(transportMsg.Data); err != nil {
		return nil, fmt.Errorf("%s: failed to unmarshal signature for %s message", operationType, err.Error())
	}

	switch operationType {
	case "resign":
		resign, ok := s.UnsignedResign[string(sig.Hash)]
		if !ok {
			return nil, fmt.Errorf("unknown resign message")
		}
		instanceMessage = s.UnsignedResign[string(sig.Hash)]
		allOps = resign.Operators

		s.Logger.Info("Incoming resign request fields",
			zap.String("network", hex.EncodeToString(resign.Resign.Fork[:])),
			zap.String("withdrawal", hex.EncodeToString(resign.Resign.WithdrawalCredentials)),
			zap.String("owner", hex.EncodeToString(resign.Resign.Owner[:])),
			zap.Uint64("nonce", resign.Resign.Nonce),
			zap.String("EIP1271 owner signature", hex.EncodeToString(sig.Signature)))
		for _, proof := range resign.Proofs {
			s.Logger.Info("Loaded proof",
				zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
				zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
				zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
				zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
				zap.String("Signature", hex.EncodeToString(proof.Signature)))
		}

	case "reshare":
		reshare, ok := s.UnsignedReshare[string(sig.Hash)]
		if !ok {
			return nil, fmt.Errorf("unknown reshare message")
		}
		instanceMessage = reshare
		allOps = append(allOps, reshare.Reshare.OldOperators...)
		allOps = append(allOps, reshare.Reshare.NewOperators...)

		s.Logger.Info("Incoming reshare request fields",
			zap.Any("Old operator IDs", utils.GetOpIDs(reshare.Reshare.OldOperators)),
			zap.Any("New operator IDs", utils.GetOpIDs(reshare.Reshare.NewOperators)),
			zap.String("ValidatorPubKey", hex.EncodeToString(reshare.Proofs[0].Proof.ValidatorPubKey)),
			zap.String("network", hex.EncodeToString(reshare.Reshare.Fork[:])),
			zap.String("withdrawal", hex.EncodeToString(reshare.Reshare.WithdrawalCredentials)),
			zap.String("owner", hex.EncodeToString(reshare.Reshare.Owner[:])),
			zap.Uint64("nonce", reshare.Reshare.Nonce),
			zap.String("EIP1271 owner signature", hex.EncodeToString(sig.Signature)))
		for _, proof := range reshare.Proofs {
			s.Logger.Info("Reshare proof",
				zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
				zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
				zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
				zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
				zap.String("Signature", hex.EncodeToString(proof.Signature)))
		}

	default:
		return nil, fmt.Errorf("unknown operation type: %s", operationType)
	}

	// verify EIP1271 signature
	hash, err := getResignOrReshare(instanceMessage)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create instance: %w", operationType, err)
	}
	if err := spec_crypto.VerifySignedMessageByOwner(
		s.EthClient,
		getOwner(instanceMessage),
		hash,
		sig.Signature,
	); err != nil {
		return nil, err
	}

	s.Logger.Info(fmt.Sprintf("✅ %s eip1271 owner signature is successfully verified", operationType), zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))

	if err := s.validateInstances(reqID); err != nil {
		return nil, err
	}

	inst, resp, err := s.CreateInstance(reqID, allOps, instanceMessage, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to create instance: %w", operationType, err)
	}

	s.Mtx.Lock()
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()

	return resp, nil
}

func (s *Switch) HandleBulkOperation(transportMsg *wire.Transport, initiatorPub, initiatorSignature []byte, operationType string) ([][]byte, error) {
	if !bytes.Equal(transportMsg.Version, s.Version) {
		return nil, fmt.Errorf("wrong version: remote %s local %s", transportMsg.Version, s.Version)
	}

	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("%s: failed to parse initiator public key: %s", operationType, err.Error())
	}
	marshalledWireMsg, err := transportMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("%s: failed to marshal transport message: %s", operationType, err.Error())
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("%s: initiator signature isn't valid: %s", operationType, err.Error())
	}

	s.Logger.Info(fmt.Sprintf("🚀 Handling %s operation", operationType))

	sig := &wire.SignatureForHash{}
	if err := sig.UnmarshalSSZ(transportMsg.Data); err != nil {
		return nil, fmt.Errorf("%s: failed to unmarshal signature for %s message", operationType, err.Error())
	}

	// resps store responses for all ceremonies
	resps := [][]byte{}
	switch operationType {
	case "reshare":
		bulk_reshare, ok := s.BulkReshare[string(sig.Hash)]
		if !ok {
			return nil, fmt.Errorf("unknown bulk reshare message")
		}

		// Verify signature for all ceremonies
		hash, err := utils.GetBulkReshareHash(bulk_reshare)
		if err != nil {
			return nil, fmt.Errorf("failed to get bulk reshare hash: %w", err)
		}
		if err := spec_crypto.VerifySignedMessageByOwner(
			s.EthClient,
			getOwner(bulk_reshare),
			hash,
			sig.Signature,
		); err != nil {
			return nil, err
		}

		// Run all reshare ceremonies
		for _, reshare := range bulk_reshare.Reshares {
			// make a unique ID for each reshare using the instance hash
			// TODO: hash is 32 bytes, but reqID is 24 bytes, may not be the best solution.
			// Potential solution is to use 32 bytes hash for all reqIDs, but need to check if it breaks anything
			reqID := [24]byte{}
			instanceHash, err := utils.GetReshareHash(reshare)
			if err != nil {
				return nil, fmt.Errorf("failed to get reshare hash: %w", err)
			}
			copy(reqID[:], instanceHash[:])
			if err := s.validateInstances(reqID); err != nil {
				return nil, err
			}

			allOps := []*spec.Operator{}
			allOps = append(allOps, reshare.Reshare.OldOperators...)
			allOps = append(allOps, reshare.Reshare.NewOperators...)

			inst, resp, err := s.CreateInstance(reqID, allOps, reshare, initiatorPubKey)
			resps = append(resps, resp)
			if err != nil {
				return nil, fmt.Errorf("%s: failed to create instance: %w", operationType, err)
			}

			s.Mtx.Lock()
			s.Instances[reqID] = inst
			s.InstanceInitTime[reqID] = time.Now()
			s.Mtx.Unlock()
		}
	default:
		return nil, fmt.Errorf("unknown operation type: %s", operationType)
	}

	return resps, nil
}

// Helper functions to abstract out common behavior
func getOwner(message interface{}) [20]byte {
	var owner [20]byte
	switch msg := message.(type) {
	case *wire.ResignMessage:
		copy(owner[:], msg.Resign.Owner[:])
	case *wire.ReshareMessage:
		copy(owner[:], msg.Reshare.Owner[:])
	case *wire.BulkReshareMessage:
		copy(owner[:], msg.Reshares[0].Reshare.Owner[:])
	}
	return owner
}

func getResignOrReshare(message interface{}) ([32]byte, error) {
	switch msg := message.(type) {
	case *wire.ResignMessage:
		hash, err := utils.GetResignHash(msg)
		if err != nil {
			return hash, err
		}
		return hash, nil
	case *wire.ReshareMessage:
		hash, err := utils.GetReshareHash(msg)
		if err != nil {
			return hash, err
		}
		return hash, nil
	default:
		return [32]byte{}, fmt.Errorf("cant infer message type")
	}
}

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
