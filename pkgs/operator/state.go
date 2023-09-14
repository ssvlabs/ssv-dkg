package operator

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	bls3 "github.com/drand/kyber-bls12381"
	"github.com/sirupsen/logrus"
)

const MaxInstances = 1024
const MaxInstanceTime = 5 * time.Minute

var ErrMissingInstance = errors.New("got message to instance that I don't have, send Init first")
var ErrAlreadyExists = errors.New("got init msg for existing instance")
var ErrMaxInstances = errors.New("max number of instances ongoing, please wait")

type Instance interface {
	Process(uint64, *wire.SignedTransport) error // maybe return resp, threadsafe
	ReadResponse() []byte
	ReadError() error
	VerifyInitiatorMessage(msg, sig []byte) error
}

type instWrapper struct {
	*dkg.LocalOwner
	respChan chan []byte
	errChan  chan error
}

func (iw *instWrapper) ReadResponse() []byte {
	return <-iw.respChan
}
func (iw *instWrapper) ReadError() error {
	return <-iw.errChan
}

type InstanceID [24]byte

func (s *Switch) CreateInstance(reqID [24]byte, init *wire.Init, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {

	verify, err := s.CreateVerifyFunc(init.Operators)
	if err != nil {
		return nil, nil, err
	}

	operatorID := uint64(0)
	operatorPubKey := s.privateKey.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodePublicKey(operatorPubKey)
	if err != nil {
		return nil, nil, err
	}
	for _, op := range init.Operators {
		if bytes.Equal(op.PubKey, pkBytes) {
			operatorID = op.ID
			break
		}
	}

	if operatorID == 0 {
		return nil, nil, errors.New("my operator is missing inside the op list")
	}

	bchan := make(chan []byte, 1)

	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}

	opts := dkg.OwnerOpts{
		Logger:             s.logger.WithField("instance", hex.EncodeToString(reqID[:])),
		BroadcastF:         broadcast,
		SignFunc:           s.Sign,
		VerifyFunc:         verify,
		Suite:              bls3.NewBLS12381Suite(),
		ID:                 operatorID,
		OpPrivKey:          s.privateKey,
		Owner:              init.Owner,
		Nonce:              init.Nonce,
		InitiatorPublicKey: initiatorPublicKey,
	}
	owner := dkg.New(opts)
	// wait for exchange msg
	resp, err := owner.Init(reqID, init)
	if err != nil {
		return nil, nil, err
	}
	if err := owner.Broadcast(resp); err != nil {
		return nil, nil, err
	}
	s.logger.Infof("Waiting for owner response to init")
	res := <-bchan
	return &instWrapper{owner, bchan, owner.ErrorChan}, res, nil
}

func (s *Switch) Sign(msg []byte) ([]byte, error) {
	return crypto.SignRSA(s.privateKey, msg)
}

func (s *Switch) CreateVerifyFunc(ops []*wire.Operator) (func(id uint64, msg []byte, sig []byte) error, error) {

	inst_ops := make(map[uint64]*rsa.PublicKey)
	for _, op := range ops {
		pk, err := crypto.ParseRSAPubkey(op.PubKey)
		if err != nil {
			return nil, err
		}
		inst_ops[op.ID] = pk
	}
	return func(id uint64, msg []byte, sig []byte) error {
		pk, ok := inst_ops[id]
		if !ok {
			return errors.New("ops not exist for this instance")
		}
		return crypto.VerifyRSA(pk, msg, sig)
	}, nil
}

type Switch struct {
	logger           *logrus.Entry
	mtx              sync.RWMutex
	instanceInitTime map[InstanceID]time.Time
	instances        map[InstanceID]Instance

	privateKey *rsa.PrivateKey

	//broadcastF func([]byte) error
}

func NewSwitch(pv *rsa.PrivateKey) *Switch {
	return &Switch{
		logger:           logrus.NewEntry(logrus.New()),
		mtx:              sync.RWMutex{},
		instanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		instances:        make(map[InstanceID]Instance, MaxInstances),
		privateKey:       pv,
	}
}

func (s *Switch) InitInstance(reqID [24]byte, initMsg *wire.Transport, initiatorSignature []byte) ([]byte, error) {
	logger := s.logger.WithField("reqid", hex.EncodeToString(reqID[:]))
	logger.Infof("initializing DKG instance")
	init := &wire.Init{}
	if err := init.UnmarshalSSZ(initMsg.Data); err != nil {
		return nil, err
	}
	s.logger.Debug("decoded init message")
	// Check that incoming init message signature is valid
	initiatorPubKey, err := crypto.ParseRSAPubkey(init.InitiatorPublicKey)
	if err != nil {
		return nil, err
	}
	marshalledWireMsg, err := initMsg.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	err = crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("init message signature isn't valid: %s", err.Error())
	}
	s.logger.Infof("init message signature is successfully verified, from: %x", sha256.Sum256(initiatorPubKey.N.Bytes()))
	s.mtx.Lock()
	l := len(s.instances)
	if l >= MaxInstances {
		cleaned := s.cleanInstances() // not thread safe
		if l-cleaned >= MaxInstances {
			s.mtx.Unlock()
			return nil, ErrMaxInstances
		}
	}
	_, ok := s.instances[reqID]
	if ok {
		tm := s.instanceInitTime[reqID]
		if !time.Now().After(tm.Add(MaxInstanceTime)) {
			s.mtx.Unlock()
			return nil, ErrAlreadyExists
		}
		delete(s.instances, reqID)
		delete(s.instanceInitTime, reqID)
	}
	s.mtx.Unlock()
	inst, resp, err := s.CreateInstance(reqID, init, initiatorPubKey)

	if err != nil {
		return nil, err
	}
	s.mtx.Lock()
	_, ok = s.instances[reqID]
	if ok {
		s.mtx.Unlock()
		return nil, ErrAlreadyExists
	}
	s.instances[reqID] = inst
	s.instanceInitTime[reqID] = time.Now()
	s.mtx.Unlock()

	return resp, nil

}

func (s *Switch) cleanInstances() int {
	count := 0
	for id, instime := range s.instanceInitTime {
		if time.Now().After(instime.Add(MaxInstanceTime)) {
			delete(s.instances, id)
			delete(s.instanceInitTime, id)
			count++
		}
	}
	return count
}

func (s *Switch) ProcessMessage(dkgMsg []byte) ([]byte, error) {
	// get instanceID
	st := &wire.MultipleSignedTransports{}
	err := st.UnmarshalSSZ(dkgMsg)
	if err != nil {
		return nil, err
	}

	id := InstanceID(st.Identifier)

	s.mtx.RLock()
	inst, ok := s.instances[id]
	s.mtx.RUnlock()

	if !ok {
		return nil, ErrMissingInstance
	}
	var mltplMsgsBytes []byte
	for _, ts := range st.Messages {
		tsBytes, err := ts.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		mltplMsgsBytes = append(mltplMsgsBytes, tsBytes...)
	}
	// Verify initiator signature
	err = inst.VerifyInitiatorMessage(mltplMsgsBytes, st.Signature)
	if err != nil {
		return nil, err
	}
	for _, ts := range st.Messages {
		err = inst.Process(ts.Signer, ts)
		if err != nil {
			return nil, err
		}
	}
	resp := inst.ReadResponse()

	return resp, nil
}
