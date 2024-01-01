package operator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"sync"
	"time"

	"github.com/drand/kyber"
	bls3 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	kyber_dkg "github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/storage/kv"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

const MaxInstances = 1024
const MaxInstanceTime = 5 * time.Minute

// Instance interface to process messages at DKG instances incoming from initiator
type Instance interface {
	Process(uint64, *wire.SignedTransport) error
	ReadResponse() []byte
	ReadError() error
	VerifyInitiatorMessage(msg, sig []byte) error
	GetLocalOwner() *dkg.LocalOwner
}

// instWrapper wraps LocalOwner instance with RSA public key
type instWrapper struct {
	*dkg.LocalOwner                   // main DKG ceremony instance
	InitiatorPublicKey *rsa.PublicKey // initiator's RSA public key to verify its identity. Makes sure that in the DKG process messages received only from one initiator who started it.
	respChan           chan []byte    // channel to receive response
	errChan            chan error     // channel to receive error
}

// VerifyInitiatorMessage verifies initiator message signature
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

// ReadResponse reads from response channel
func (iw *instWrapper) ReadResponse() []byte {
	return <-iw.respChan
}

// ReadError reads from error channel
func (iw *instWrapper) ReadError() error {
	return <-iw.errChan
}

// InstanceID each new DKG ceremony has a unique random ID that we can identify messages and be able to process them in parallel
type InstanceID [24]byte

// Switch structure to hold many instances created for separate DKG ceremonies
type Switch struct {
	Logger           *zap.Logger
	Mtx              sync.RWMutex
	InstanceInitTime map[InstanceID]time.Time // mapping to store DKG instance creation time
	Instances        map[InstanceID]Instance  // mapping to store DKG instances
	PrivateKey       *rsa.PrivateKey          // operator RSA private key
	DB               *kv.BadgerDB
	Version          []byte
	PubKeyBytes      []byte
	OperatorID       uint64
}

// CreateInstance creates a LocalOwner instance with the DKG ceremony ID, that we can identify it later. Initiator public key identifies an initiator for
// new instance. There cant be two instances with the same ID, but one initiator can start several DKG ceremonies.
func (s *Switch) CreateInstance(reqID [24]byte, init *wire.Init, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {
	verify, err := s.CreateVerifyFunc(init.Operators)
	if err != nil {
		return nil, nil, err
	}
	operatorID, err := GetOperatorID(init.Operators, s.PubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	bchan := make(chan []byte, 1)
	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}
	opts := dkg.OwnerOpts{
		Logger:               s.Logger.With(zap.String("instance", hex.EncodeToString(reqID[:]))),
		BroadcastF:           broadcast,
		SignFunc:             s.Sign,
		VerifyFunc:           verify,
		EncryptFunc:          s.Encrypt,
		DecryptFunc:          s.Decrypt,
		StoreSecretShareFunc: s.StoreSecretShare,
		Suite:                bls3.NewBLS12381Suite(),
		ID:                   operatorID,
		RSAPub:               &s.PrivateKey.PublicKey,
		Owner:                init.Owner,
		Nonce:                init.Nonce,
		Version:              s.Version,
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

func (s *Switch) CreateInstanceReshare(reqID [24]byte, reshare *wire.Reshare, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {
	allOps := append(reshare.OldOperators, reshare.NewOperators...)
	verify, err := s.CreateVerifyFunc(allOps)
	if err != nil {
		return nil, nil, err
	}
	operatorID, err := GetOperatorID(allOps, s.PubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	bchan := make(chan []byte, 1)
	broadcast := func(msg []byte) error {
		bchan <- msg
		return nil
	}
	opts := dkg.OwnerOpts{
		Logger:               s.Logger.With(zap.String("instance", hex.EncodeToString(reqID[:]))),
		BroadcastF:           broadcast,
		SignFunc:             s.Sign,
		EncryptFunc:          s.Encrypt,
		DecryptFunc:          s.Decrypt,
		VerifyFunc:           verify,
		StoreSecretShareFunc: s.StoreSecretShare,
		Suite:                bls3.NewBLS12381Suite(),
		ID:                   operatorID,
		RSAPub:               &s.PrivateKey.PublicKey,
		Owner:                reshare.Owner,
		Nonce:                reshare.Nonce,
		Version:              s.Version,
	}
	owner := dkg.New(opts)
	// wait for exchange msg
	var secretShare *kyber_dkg.DistKeyShare
	var commits []byte
	for _, op := range reshare.OldOperators {
		if owner.ID == op.ID {
			// try to get old share local owner first
			pub, err := crypto.EncodePublicKey(initiatorPublicKey)
			if err != nil {
				return nil, nil, err
			}
			secretShare, err = s.GetSecretShare(reshare.OldID, pub)
			if err != nil {
				return nil, nil, err
			}
			owner.SecretShare = secretShare
			for _, point := range secretShare.Commits {
				b, err := point.MarshalBinary()
				if err != nil {
					return nil, nil, fmt.Errorf("failed to marshal commit: %s", err.Error())
				}
				commits = append(commits, b...)
			}
			break
		}
	}
	resp, err := owner.InitReshare(reqID, reshare, commits)
	if err != nil {
		return nil, nil, err
	}
	if err := owner.Broadcast(resp); err != nil {
		return nil, nil, err
	}
	res := <-bchan
	return &instWrapper{owner, initiatorPublicKey, bchan, owner.ErrorChan}, res, nil
}

// Sign creates a RSA signature for the message at operator before sending it to initiator
func (s *Switch) Sign(msg []byte) ([]byte, error) {
	return crypto.SignRSA(s.PrivateKey, msg)
}

// Encrypt with RSA public key private DKG share key
func (s *Switch) Encrypt(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, msg)
}

// Decrypt with RSA private key private DKG share key
func (s *Switch) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsaencryption.DecodeKey(s.PrivateKey, ciphertext)
}

// StoreSecretShare stores to Badger DB a secret share encrypted with RSA priv key
func (s *Switch) StoreSecretShare(reqID [24]byte, pubKey []byte, key *kyber_dkg.DistKeyShare) error {
	// encode priv share
	secret := &dkg.DistKeyShare{}
	secret.Commits = utils.CommitsToBytes(key.Commits)
	secterPoint, err := key.Share.V.MarshalBinary()
	if err != nil {
		return err
	}
	secret.Share.V = secterPoint
	secret.Share.I = key.Share.I
	bin, err := secret.Encode()
	if err != nil {
		return err
	}
	encBin, err := s.EncryptSecretDB(bin)
	if err != nil {
		return err
	}
	err = s.DB.Set(pubKey, reqID[:], encBin)
	if err != nil {
		return err
	}
	return nil
}

// EncryptSecretDB encrypts secret share object bytes using RSA key to store at DB
func (s *Switch) EncryptSecretDB(bin []byte) ([]byte, error) {
	// brake to chunks of 256 byte
	chuncks := utils.SplitBytes(bin, 128)
	var encrypted []byte
	for _, chunk := range chuncks {
		encBin, err := s.Encrypt(chunk)
		if err != nil {
			return nil, err
		}
		encrypted = append(encrypted, encBin...)
	}
	return encrypted, nil
}

// CreateVerifyFunc verifies signatures for operators participating at DKG ceremony
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

// NewSwitch creates a new Switch
func NewSwitch(pv *rsa.PrivateKey, logger *zap.Logger, db *kv.BadgerDB, ver []byte, pkBytes []byte, id uint64) *Switch {
	return &Switch{
		Logger:           logger,
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		Instances:        make(map[InstanceID]Instance, MaxInstances),
		PrivateKey:       pv,
		DB:               db,
		Version:          ver,
		PubKeyBytes:      pkBytes,
		OperatorID:       id,
	}
}

// InitInstance creates a LocalOwner instance and DKG public key message (Exchange)
func (s *Switch) InitInstance(reqID [24]byte, initMsg *wire.Transport, initiatorSignature []byte) ([]byte, error) {
	if !bytes.Equal(initMsg.Version, s.Version) {
		return nil, utils.ErrVersion
	}
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqID[:])))
	logger.Info("🚀 Initializing DKG instance")
	init := &wire.Init{}
	if err := init.UnmarshalSSZ(initMsg.Data); err != nil {
		return nil, fmt.Errorf("init: failed to unmarshal init message: %s", err.Error())
	}
	// Check that incoming message signature is valid
	initiatorPubKey, err := crypto.ParseRSAPubkey(init.InitiatorPublicKey)
	if err != nil {
		return nil, fmt.Errorf("init: failed parse initiator public key: %s", err.Error())
	}
	marshalledWireMsg, err := initMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("init: failed to marshal transport message: %s", err.Error())
	}
	err = crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("init: initiator signature isn't valid: %s", err.Error())
	}
	s.Logger.Info("✅ init message signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes()[:])))
	s.Mtx.Lock()
	l := len(s.Instances)
	if l >= MaxInstances {
		cleaned := s.CleanInstances()
		if l-cleaned >= MaxInstances {
			s.Mtx.Unlock()
			return nil, utils.ErrMaxInstances
		}
	}
	_, ok := s.Instances[reqID]
	if ok {
		tm := s.InstanceInitTime[reqID]
		if !time.Now().After(tm.Add(MaxInstanceTime)) {
			s.Mtx.Unlock()
			return nil, utils.ErrAlreadyExists
		}
		delete(s.Instances, reqID)
		delete(s.InstanceInitTime, reqID)
	}
	s.Mtx.Unlock()
	// check if we already run with reqID
	if _, err := s.GetSecretShare(reqID, init.InitiatorPublicKey); err == nil { // we already had initial ceremony with reqID
		return nil, utils.ErrAlreadyExists
	}
	inst, resp, err := s.CreateInstance(reqID, init, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("init: failed to create instance: %s", err.Error())
	}
	s.Mtx.Lock()
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

func (s *Switch) InitInstanceReshare(reqID [24]byte, reshareMsg *wire.Transport, initiatorSignature []byte) ([]byte, error) {
	if !bytes.Equal(reshareMsg.Version, s.Version) {
		return nil, utils.ErrVersion
	}
	logger := s.Logger.With(zap.String("reqid", hex.EncodeToString(reqID[:])))
	logger.Info("🚀 Initializing DKG instance")
	reshare := &wire.Reshare{}
	if err := reshare.UnmarshalSSZ(reshareMsg.Data); err != nil {
		return nil, err
	}
	// Check that incoming message signature is valid
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
	s.Logger.Info("✅ reshare message signature is successfully verified", zap.String("from initiator pub key", fmt.Sprintf("%x", initiatorPubKey.N.Bytes()[:])))
	s.Logger.Info("Starting resharing protocol")
	s.Mtx.Lock()
	l := len(s.Instances)
	if l >= MaxInstances {
		cleaned := s.CleanInstances() // not thread safe
		if l-cleaned >= MaxInstances {
			s.Mtx.Unlock()
			return nil, utils.ErrMaxInstances
		}
	}
	_, ok := s.Instances[reqID]
	if ok {
		tm := s.InstanceInitTime[reqID]
		if !time.Now().After(tm.Add(MaxInstanceTime)) {
			s.Mtx.Unlock()
			return nil, utils.ErrAlreadyExists
		}
		delete(s.Instances, reqID)
		delete(s.InstanceInitTime, reqID)
	}
	s.Mtx.Unlock()
	// check if we already run with reqID
	if _, err := s.GetSecretShare(reqID, reshare.InitiatorPublicKey); err == nil { // we already had initial ceremony with reqID
		return nil, utils.ErrAlreadyExists
	}
	inst, resp, err := s.CreateInstanceReshare(reqID, reshare, initiatorPubKey)
	if err != nil {
		return nil, err
	}
	s.Mtx.Lock()
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

// CleanInstances removes all instances at Switch
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
	var mltplMsgsBytes []byte
	for _, ts := range st.Messages {
		tsBytes, err := ts.MarshalSSZ()
		if err != nil {
			return nil, fmt.Errorf("process message: failed to marshal message: %s", err.Error())
		}
		mltplMsgsBytes = append(mltplMsgsBytes, tsBytes...)
	}
	// Verify initiator signature
	err = inst.VerifyInitiatorMessage(mltplMsgsBytes, st.Signature)
	if err != nil {
		return nil, fmt.Errorf("process message: failed to verify initiator signature: %s", err.Error())
	}
	for _, ts := range st.Messages {
		err = inst.Process(ts.Signer, ts)
		if err != nil {
			return nil, fmt.Errorf("process message: failed to process dkg message: %s", err.Error())
		}
	}
	resp := inst.ReadResponse()

	return resp, nil
}

// DecryptSecretDB decrypts a secret share using operator's private key
func (s *Switch) DecryptSecretDB(bin []byte) ([]byte, error) {
	// brake to chunks of 256 byte
	chuncks := utils.SplitBytes(bin, 256)
	var decrypted []byte
	for _, chunk := range chuncks {
		decBin, err := s.Decrypt(chunk)
		if err != nil {
			return nil, err
		}
		decrypted = append(decrypted, decBin...)
	}
	return decrypted, nil
}

// GetSecretShare creates a secret share object from encrypted DB value
func (s *Switch) GetSecretShare(id [24]byte, pubKey []byte) (*kyber_dkg.DistKeyShare, error) {
	shareFromDB, ok, err := s.DB.Get(pubKey, id[:])
	if err != nil {
		return nil, err
	}
	if !ok {
		return nil, fmt.Errorf("secret share for pub key and ID not found")
	}
	decBin, err := s.DecryptSecretDB(shareFromDB.Value)
	if err != nil {
		return nil, err
	}
	var privShare dkg.DistKeyShare
	err = privShare.Decode(decBin)
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
	secretPoint := bls3.NewBLS12381Suite().G1().Scalar()
	err = secretPoint.UnmarshalBinary(privShare.Share.V)
	if err != nil {
		return nil, err
	}
	return &kyber_dkg.DistKeyShare{Share: &share.PriShare{V: secretPoint, I: privShare.Share.I}, Commits: coefs}, nil
}

func (s *Switch) Pong() ([]byte, error) {
	pong := &wire.Pong{
		PubKey: s.PubKeyBytes,
	}
	return s.MarshallAndSign(pong, wire.PongMessageType, s.OperatorID, [24]byte{})
}

func (s *Switch) SaveResultData(incMsg *wire.SignedTransport) error {
	resData := &wire.ResultData{}
	if err := resData.UnmarshalSSZ(incMsg.Message.Data); err != nil {
		return err
	}
	_, err := s.VerifyIncomingMessage(incMsg)
	if err != nil {
		return err
	}
	// store deposit result
	timestamp := time.Now().Format(time.RFC3339Nano)
	dir := fmt.Sprintf("%s/ceremony-%s", cli_utils.OutputPath, timestamp)
	if _, err := os.Stat(dir); os.IsNotExist(err) {
		err = os.Mkdir(dir, os.ModePerm)
		if err != nil {
			return err
		}
	}
	var depJson *initiator.DepositDataJson
	if len(resData.DepositData) != 0 {
		err = json.Unmarshal(resData.DepositData, &depJson)
		if err != nil {
			return err
		}
		err = cli_utils.WriteDepositResult(depJson, dir)
		if err != nil {
			return err
		}
	}
	// store keyshares result
	var ksJson *initiator.KeyShares
	if len(resData.KeysharesData) != 0 {
		err = json.Unmarshal(resData.KeysharesData, &ksJson)
		if err != nil {
			return err
		}
		err = cli_utils.WriteKeysharesResult(ksJson, dir, incMsg.Message.Identifier)
		if err != nil {
			return err
		}
	}
	// store instance ID
	err = cli_utils.WriteInstanceID(dir, incMsg.Message.Identifier)
	if err != nil {
		return err
	}
	return nil
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
		initiatorPubKey, err = crypto.ParseRSAPubkey(ping.InitiatorPublicKey)
		if err != nil {
			return 0, err
		}
		ops = ping.Operators
		err = s.VerifySig(incMsg, initiatorPubKey)
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

func (s *Switch) VerifySig(incMsg *wire.SignedTransport, initiatorPubKey *rsa.PublicKey) error {
	marshalledWireMsg, err := incMsg.Message.MarshalSSZ()
	if err != nil {
		return err
	}
	err = crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, incMsg.Signature)
	if err != nil {
		return fmt.Errorf("signature isn't valid: %s", err.Error())
	}
	return nil
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
		Signer:    operatorID,
		Signature: sign,
	}

	return signed.MarshalSSZ()
}
