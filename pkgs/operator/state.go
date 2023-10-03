package operator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"sync"
	"time"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/bloxapp/ssv/storage/kv"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/drand/kyber"
	bls3 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	kyber_dkg "github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"
)

const MaxInstances = 1024
const MaxInstanceTime = 5 * time.Minute

var ErrMissingInstance = errors.New("got message to instance that I don't have, send Init first")
var ErrAlreadyExists = errors.New("got init msg for existing instance")
var ErrMaxInstances = errors.New("max number of instances ongoing, please wait")

type Instance interface {
	Process(uint64, *wire.SignedTransport) error
	ReadResponse() []byte
	ReadError() error
	VerifyInitiatorMessage(msg, sig []byte) error
}

type instWrapper struct {
	*dkg.LocalOwner
	InitiatorPublicKey *rsa.PublicKey
	respChan           chan []byte
	errChan            chan error
}

func (iw *instWrapper) VerifyInitiatorMessage(msg []byte, sig []byte) error {
	pubKey, err := crypto.EncodePublicKey(iw.InitiatorPublicKey)
	if err != nil {
		return err
	}
	if err := crypto.VerifyRSA(iw.InitiatorPublicKey, msg, sig); err != nil {
		return fmt.Errorf("failed to verify a message from initiator: %x", pubKey)
	}
	iw.Logger.Info("Successfully verified initiator message signature", zap.Uint64("from", iw.ID))
	return nil
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
	operatorPubKey := s.PrivateKey.Public().(*rsa.PublicKey)
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
		return nil, nil, errors.New("my operator is missing inside the operators list at instance")
	}
	bchan := make(chan []byte, 1)
	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}

	opts := dkg.OwnerOpts{
		Logger:      s.Logger.With(zap.String("instance", hex.EncodeToString(reqID[:]))),
		BroadcastF:  broadcast,
		SignFunc:    s.Sign,
		VerifyFunc:  verify,
		EncryptFunc: s.Encrypt,
		DecryptFunc: s.Decrypt,
		Suite:       bls3.NewBLS12381Suite(),
		ID:          operatorID,
		RSAPub:      &s.PrivateKey.PublicKey,
		Owner:       init.Owner,
		Nonce:       init.Nonce,
		DB:          s.DB,
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
	res := <-bchan
	return &instWrapper{owner, initiatorPublicKey, bchan, owner.ErrorChan}, res, nil
}

func (s *Switch) CreateInstanceReshare(reqID [24]byte, reshare *wire.Reshare, initiatorPublicKey *rsa.PublicKey, secretShare *kyber_dkg.DistKeyShare) (Instance, []byte, error) {
	allOps := append(reshare.OldOperators, reshare.NewOperators...)
	verify, err := s.CreateVerifyFunc(allOps)
	if err != nil {
		return nil, nil, err
	}
	operatorID := uint64(0)
	operatorPubKey := s.PrivateKey.Public().(*rsa.PublicKey)
	pkBytes, err := crypto.EncodePublicKey(operatorPubKey)
	if err != nil {
		return nil, nil, err
	}
	for _, op := range allOps {
		if bytes.Equal(op.PubKey, pkBytes) {
			operatorID = op.ID
			break
		}
	}
	if operatorID == 0 {
		return nil, nil, errors.New("my operator is missing inside the old operators list at instance")
	}

	bchan := make(chan []byte, 1)
	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}
	opts := dkg.OwnerOpts{
		Logger:      s.Logger.With(zap.String("instance", hex.EncodeToString(reqID[:]))),
		BroadcastF:  broadcast,
		SignFunc:    s.Sign,
		EncryptFunc: s.Encrypt,
		DecryptFunc: s.Decrypt,
		VerifyFunc:  verify,
		Suite:       bls3.NewBLS12381Suite(),
		ID:          operatorID,
		RSAPub:      &s.PrivateKey.PublicKey,
		Owner:       reshare.Owner,
		Nonce:       reshare.Nonce,
		DB:          s.DB,
	}
	owner := dkg.New(opts)
	// wait for exchange msg
	var commits []byte
	if secretShare != nil {
		owner.SecretShare = secretShare
		for _, point := range secretShare.Commits {
			b, _ := point.MarshalBinary()
			commits = append(commits, b...)
		}
	}
	resp, err := owner.CreateInstanceReshare(reqID, reshare, commits)
	if err != nil {
		return nil, nil, err
	}
	if err := owner.Broadcast(resp); err != nil {
		return nil, nil, err
	}
	res := <-bchan
	return &instWrapper{owner, initiatorPublicKey, bchan, owner.ErrorChan}, res, nil
}

func (s *Switch) Sign(msg []byte) ([]byte, error) {
	return crypto.SignRSA(s.PrivateKey, msg)
}

func (s *Switch) Encrypt(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, msg)
}

func (s *Switch) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsaencryption.DecodeKey(s.PrivateKey, ciphertext)
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
			return fmt.Errorf("cant find operator participating at DKG %d", id)
		}
		return crypto.VerifyRSA(pk, msg, sig)
	}, nil
}

type Switch struct {
	Logger           *zap.Logger
	Mtx              sync.RWMutex
	InstanceInitTime map[InstanceID]time.Time
	Instances        map[InstanceID]Instance

	PrivateKey *rsa.PrivateKey
	DB         *kv.BadgerDB

	//broadcastF func([]byte) error
}

func NewSwitch(pv *rsa.PrivateKey, logger *zap.Logger, db *kv.BadgerDB) *Switch {
	return &Switch{
		Logger:           logger,
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		Instances:        make(map[InstanceID]Instance, MaxInstances),
		PrivateKey:       pv,
		DB:               db,
	}
}

func (s *Switch) InitInstance(reqID [24]byte, initMsg *wire.Transport, initiatorSignature []byte) ([]byte, error) {
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqID[:])))
	logger.Info("🚀 Initializing DKG instance")
	init := &wire.Init{}
	if err := init.UnmarshalSSZ(initMsg.Data); err != nil {
		return nil, err
	}
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
		return nil, fmt.Errorf("init message: initiator signature isn't valid: %s", err.Error())
	}
	initiatorID := sha256.Sum256(initiatorPubKey.N.Bytes())
	s.Logger.Info("✅ init message signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorID[:])))
	s.Mtx.Lock()
	l := len(s.Instances)
	if l >= MaxInstances {
		cleaned := s.CleanInstances()
		if l-cleaned >= MaxInstances {
			s.Mtx.Unlock()
			return nil, ErrMaxInstances
		}
	}
	_, ok := s.Instances[reqID]
	if ok {
		tm := s.InstanceInitTime[reqID]
		if !time.Now().After(tm.Add(MaxInstanceTime)) {
			s.Mtx.Unlock()
			return nil, ErrAlreadyExists
		}
		delete(s.Instances, reqID)
		delete(s.InstanceInitTime, reqID)
	}
	s.Mtx.Unlock()
	inst, resp, err := s.CreateInstance(reqID, init, initiatorPubKey)

	if err != nil {
		return nil, err
	}
	s.Mtx.Lock()
	_, ok = s.Instances[reqID]
	if ok {
		s.Mtx.Unlock()
		return nil, ErrAlreadyExists
	}
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

func (s *Switch) InitInstanceReshare(reqID [24]byte, reshareMsg *wire.Transport, initiatorSignature []byte) ([]byte, error) {
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqID[:])))
	logger.Info("🚀 Initializing DKG instance")
	reshare := &wire.Reshare{}
	if err := reshare.UnmarshalSSZ(reshareMsg.Data); err != nil {
		return nil, err
	}
	// Check that incoming init message signature is valid
	initiatorPubKey, err := crypto.ParseRSAPubkey(reshare.InitiatorPublicKey)
	if err != nil {
		return nil, err
	}
	marshalledWireMsg, err := reshareMsg.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	err = crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("init message: initiator signature isn't valid: %s", err.Error())
	}
	initiatorID := sha256.Sum256(initiatorPubKey.N.Bytes())
	s.Logger.Info("✅ reshare message signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorID[:])))

	s.Logger.Info("Starting resharing protocol")
	// try to get old share local owner first
	var shareFromDB basedb.Obj
	secret := &kyber_dkg.DistKeyShare{}
	shareFromDB, ok, err := s.DB.Get([]byte("secret"), reshare.OldID[:])
	if err != nil {
		return nil, err
	}
	if ok {
		var privShare dkg.DistKeyShare
		err := privShare.Decode(shareFromDB.Value)
		if err != nil {
			return nil, err
		}
		var coefs []kyber.Point
		coefsBytes := utils.SplitBytes(privShare.Commits, 48)
		for _, c := range coefsBytes {
			p := bls3.NewBLS12381Suite().G1().Point()
			err := p.UnmarshalBinary(c)
			if err != nil {
				return nil, err
			}
			coefs = append(coefs, p)
		}
		secret.Commits = coefs
		secretPoint := bls3.NewBLS12381Suite().G1().Scalar()
		err = secretPoint.UnmarshalBinary(privShare.Share.V)
		if err != nil {
			return nil, err
		}
		secret.Share = &share.PriShare{V: secretPoint, I: privShare.Share.I}
		s.Mtx.Lock()
		l := len(s.Instances)
		if l >= MaxInstances {
			cleaned := s.CleanInstances() // not thread safe
			if l-cleaned >= MaxInstances {
				s.Mtx.Unlock()
				return nil, ErrMaxInstances
			}
		}
		_, ok = s.Instances[reqID]
		if ok {
			tm := s.InstanceInitTime[reqID]
			if !time.Now().After(tm.Add(MaxInstanceTime)) {
				s.Mtx.Unlock()
				return nil, ErrAlreadyExists
			}
			delete(s.Instances, reqID)
			delete(s.InstanceInitTime, reqID)
		}
		s.Mtx.Unlock()
		inst, resp, err := s.CreateInstanceReshare(reqID, reshare, initiatorPubKey, secret)
		if err != nil {
			return nil, err
		}
		s.Mtx.Lock()
		_, ok = s.Instances[reqID]
		if ok {
			s.Mtx.Unlock()
			return nil, ErrAlreadyExists
		}
		s.Instances[reqID] = inst
		s.InstanceInitTime[reqID] = time.Now()
		s.Mtx.Unlock()
		return resp, nil
	}
	s.Mtx.Lock()
	l := len(s.Instances)
	if l >= MaxInstances {
		cleaned := s.CleanInstances() // not thread safe
		if l-cleaned >= MaxInstances {
			s.Mtx.Unlock()
			return nil, ErrMaxInstances
		}
	}
	_, ok = s.Instances[reqID]
	if ok {
		tm := s.InstanceInitTime[reqID]
		if !time.Now().After(tm.Add(MaxInstanceTime)) {
			s.Mtx.Unlock()
			return nil, ErrAlreadyExists
		}
		delete(s.Instances, reqID)
		delete(s.InstanceInitTime, reqID)
	}
	s.Mtx.Unlock()
	inst, resp, err := s.CreateInstanceReshare(reqID, reshare, initiatorPubKey, nil)
	if err != nil {
		return nil, err
	}
	s.Mtx.Lock()
	_, ok = s.Instances[reqID]
	if ok {
		s.Mtx.Unlock()
		return nil, ErrAlreadyExists
	}
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

func (s *Switch) CleanInstances() int {
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

func (s *Switch) ProcessMessage(dkgMsg []byte) ([]byte, error) {
	// get instanceID
	st := &wire.MultipleSignedTransports{}
	err := st.UnmarshalSSZ(dkgMsg)
	if err != nil {
		return nil, err
	}

	id := InstanceID(st.Identifier)

	s.Mtx.RLock()
	inst, ok := s.Instances[id]
	s.Mtx.RUnlock()

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
