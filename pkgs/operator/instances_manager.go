package operator

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"go.uber.org/zap"
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
		resp, err = owner.Reshare(reqID, &msg.SignedReshare.Reshare, commits)
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
