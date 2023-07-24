package server

import (
	"crypto/rsa"
	"encoding/hex"
	"errors"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	bls "github.com/drand/kyber-bls12381"
	"github.com/sirupsen/logrus"
	"sync"
	"time"
)

const MaxInstances = 1024
const MaxInstanceTime = 5 * time.Minute

var ErrMissingInstance = errors.New("got message to instance that I don't have, send Init first")
var ErrAlreadyExists = errors.New("got init msg for existing instance")
var ErrMaxInstances = errors.New("max number of instances ongoing, please wait")

type Instance interface {
	Process(uint64, []byte) error // maybe return resp, threadsafe
	ReadResponse() []byte
}

type instWrapper struct {
	*dkg.LocalOwner
	respChan chan []byte
}

func (iw *instWrapper) ReadResponse() []byte {
	return <-iw.respChan
}

type InstanceID [24]byte

func (s *Switch) CreateInstance(reqID [24]byte, init *wire.Init) (Instance, []byte, error) {

	verify, err := s.CreateVerifyFunc(init.Operators)
	if err != nil {
		return nil, nil, err
	}

	bchan := make(chan []byte, 1)

	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}

	opts := dkg.OwnerOpts{
		Logger:     s.logger.WithField("instance", hex.EncodeToString(reqID[:])),
		BroadcastF: broadcast,
		SignFunc:   s.Sign,
		VerifyFunc: verify,
		Suite:      bls.NewBLS12381Suite(),
		//Init:       init,
	}
	owner := dkg.New(opts)
	// wait for exchange msg
	resp, err := owner.Init(reqID, init)
	if err := owner.Broadcast(resp); err != nil {
		return nil, nil, err
	}
	s.logger.Infof("Waiting for owner response to init")

	res := <-bchan

	return &instWrapper{owner, bchan}, res, nil
}

func (s *Switch) Sign(msg []byte) ([]byte, error) {
	return crypto.SignRSA(s.privateKey, msg)
}

func (s *Switch) CreateVerifyFunc(ops []uint64) (func(id uint64, msg []byte, sig []byte) error, error) {
	inst_ops := make(map[uint64]struct{})
	for _, op := range ops {
		if _, ok := s.opList[op]; !ok {
			return nil, errors.New("operator doesn't exist")
		}
		inst_ops[op] = struct{}{}
	}
	return func(id uint64, msg []byte, sig []byte) error {
		_, ok := inst_ops[id]
		if !ok {
			return errors.New("ops not exist for this instance")
		}
		k, _ := s.opList[id] // should never be !ok since we check on creation
		return crypto.VerifyRSA(k, msg, sig)
	}, nil
}

type Switch struct {
	logger           *logrus.Entry
	mtx              sync.RWMutex
	instanceInitTime map[InstanceID]time.Time
	instances        map[InstanceID]Instance

	privateKey *rsa.PrivateKey

	opList map[uint64]*rsa.PublicKey

	//broadcastF func([]byte) error
}

func NewSwitch(pv *rsa.PrivateKey, opList map[uint64]*rsa.PublicKey) *Switch {
	return &Switch{
		logger:           logrus.NewEntry(logrus.New()),
		mtx:              sync.RWMutex{},
		instanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		instances:        make(map[InstanceID]Instance, MaxInstances),
		//broadcastF:       broadcastF,
		privateKey: pv,
		opList:     opList,
	}
}

// TODO: does this improve anything over just locking everything?
//func (s *Switch) InitInstance(reqID InstanceID, init []byte) ([]byte, error) {
//
//	s.mtx.RLock()
//	l := len(s.instances)
//	if l <= MaxInstances {
//		s.mtx.Lock()
//		cleaned := s.cleanInstances()
//		if l-cleaned <= MaxInstances {
//			s.mtx.RUnlock()
//			s.mtx.Unlock()
//			return nil, ErrMaxInstances
//		}
//	}
//	_, ok := s.instances[init.ReqID]
//	if ok {
//		tm := s.instanceInitTime[init.ReqID]
//		if !time.Now().After(tm.Add(MaxInstanceTime)) {
//			s.mtx.RUnlock()
//			return nil, ErrAlreadyExists
//		}
//		s.mtx.Lock()
//		delete(s.instances, init.ReqID)
//		delete(s.instanceInitTime, init.ReqID)
//		s.mtx.Unlock()
//		s.mtx.RUnlock()
//	}
//	inst, err := CreateInstance(init) // long action? if not maybe put inside mutex to reduce lock complexity?
//	if err != nil {
//		return nil, err
//	}
//	s.mtx.Lock()
//	_, ok = s.instances[init.ReqID]
//	if ok {
//		s.mtx.RUnlock()
//		s.mtx.Unlock()
//		return nil, ErrAlreadyExists // created before us?
//	}
//	s.instances[init.ReqID] = inst
//	s.mtx.RUnlock()
//	s.mtx.Unlock()
//
//	// TODO: get some ret from inst
//	return inst.Start()
//
//}

func (s *Switch) InitInstance(reqID [24]byte, initmsg []byte) ([]byte, error) {
	logger := s.logger.WithField("reqid", hex.EncodeToString(reqID[:]))
	logger.Infof("Got an init message")
	init := &wire.Init{}
	if err := init.UnmarshalSSZ(initmsg); err != nil {
		return nil, err
	}

	s.logger.Infof("decoded init message")

	s.mtx.Lock()
	l := len(s.instances)
	if l >= MaxInstances {
		cleaned := s.cleanInstances() // not thread safe
		if l-cleaned <= MaxInstances {
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
	inst, resp, err := s.CreateInstance(reqID, init) // long action? if not maybe put inside mutex to reduce lock complexity?

	logger.Infof("Created instance")

	if err != nil {
		return nil, err
	}
	s.mtx.Lock()
	_, ok = s.instances[reqID]
	if ok {
		s.mtx.Unlock()
		return nil, ErrAlreadyExists // created before us?
	}
	s.instances[reqID] = inst
	s.mtx.Unlock()

	// TODO: get some ret from inst
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

	for _, ts := range st.Messages {

		err = inst.Process(ts.Signer, dkgMsg)
		if err != nil {
			return nil, err
		}

	}
	resp := inst.ReadResponse()

	return resp, nil
}
