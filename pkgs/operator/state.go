package operator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	kyber_bls12381 "github.com/drand/kyber-bls12381"
	kyber_dkg "github.com/drand/kyber/share/dkg"
	eth_common "github.com/ethereum/go-ethereum/common"
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/dkg-spec/eip1271"
	"go.uber.org/zap"

	cli_utils "github.com/bloxapp/ssv-dkg/cli/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

const MaxInstances = 1024
const MaxInstanceTime = 5 * time.Minute

// Instance interface to process messages at DKG instances incoming from initiator
type Instance interface {
	Process(*wire.SignedTransport, []*spec.Operator) error
	ReadResponse() []byte
	ReadError() error
	VerifyInitiatorMessage(msg, sig []byte) error
	GetLocalOwner() *dkg.LocalOwner
	CheckIncomingOperators([]*wire.SignedTransport) (map[uint64]*spec.Operator, error)
}

// instWrapper wraps LocalOwner instance with RSA public key
type instWrapper struct {
	*dkg.LocalOwner                   // main DKG ceremony instance
	InitiatorPublicKey *rsa.PublicKey // initiator's RSA public key to verify its identity. Makes sure that in the DKG process messages received only from one initiator who started it.
	respChan           chan []byte    // channel to receive response
	errChan            chan error     // channel to receive error
}

// VerifyInitiatorMessage verifies initiator message signature
func (iw *instWrapper) VerifyInitiatorMessage(msg, sig []byte) error {
	pubKey, err := spec_crypto.EncodeRSAPublicKey(iw.InitiatorPublicKey)
	if err != nil {
		return err
	}
	if err := spec_crypto.VerifyRSA(iw.InitiatorPublicKey, msg, sig); err != nil {
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
	Version          []byte
	PubKeyBytes      []byte
	OperatorID       uint64
	EthClient        eip1271.ETHClient
}

// CreateInstance creates a LocalOwner instance with the DKG ceremony ID, that we can identify it later. Initiator public key identifies an initiator for
// new instance. There cant be two instances with the same ID, but one initiator can start several DKG ceremonies.
func (s *Switch) CreateInitInstance(reqID [24]byte, init *spec.Init, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {
	operatorID, err := spec.OperatorIDByPubKey(init.Operators, s.PubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	// sanity check of operator ID
	if s.OperatorID != operatorID {
		return nil, nil, fmt.Errorf("wrong operator ID")
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

// CreateInstance creates a LocalOwner instance with the DKG ceremony ID, that we can identify it later. Initiator public key identifies an initiator for
// new instance. There cant be two instances with the same ID, but one initiator can start several DKG ceremonies.
func (s *Switch) CreateResignInstance(reqID [24]byte, resign *wire.ResignMessage, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {
	operatorID, err := spec.OperatorIDByPubKey(resign.Operators, s.PubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	// sanity check of operator ID
	if s.OperatorID != operatorID {
		return nil, nil, fmt.Errorf("wrong operator ID")
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
	resp, err := owner.Resign(reqID, resign)
	if err != nil {
		return nil, nil, err
	}
	if err := owner.Broadcast(resp); err != nil {
		return nil, nil, err
	}
	res := <-bchan
	return &instWrapper{owner, initiatorPublicKey, bchan, owner.ErrorChan}, res, nil
}

func (s *Switch) CreateReshareInstance(reqID [24]byte, reshareMsg *wire.ReshareMessage, initiatorPublicKey *rsa.PublicKey) (Instance, []byte, error) {
	var allOps []*spec.Operator
	allOps = append(allOps, reshareMsg.SignedReshare.Reshare.OldOperators...)
	allOps = append(allOps, reshareMsg.SignedReshare.Reshare.NewOperators...)
	operatorID, err := spec.OperatorIDByPubKey(allOps, s.PubKeyBytes)
	if err != nil {
		return nil, nil, err
	}
	// sanity check of operator ID
	if s.OperatorID != operatorID {
		return nil, nil, fmt.Errorf("wrong operator ID")
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
		Owner:              reshareMsg.SignedReshare.Reshare.Owner,
		Nonce:              reshareMsg.SignedReshare.Reshare.Nonce,
		Version:            s.Version,
	}
	owner := dkg.New(&opts)
	// sanity check for incoming proofs len
	if len(reshareMsg.Proofs) != len(reshareMsg.SignedReshare.Reshare.OldOperators) {
		return nil, nil, fmt.Errorf("wrong proofs len at reshare message: expected %d, got %d", len(reshareMsg.SignedReshare.Reshare.OldOperators), len(reshareMsg.Proofs))
	}
	// wait for exchange msg
	commits, err := crypto.GetPubCommitsFromProofs(reshareMsg.SignedReshare.Reshare.OldOperators, reshareMsg.Proofs, int(reshareMsg.SignedReshare.Reshare.OldT))
	if err != nil {
		return nil, nil, err
	}
	for i, op := range reshareMsg.SignedReshare.Reshare.OldOperators {
		if op.ID == s.OperatorID {
			op := &spec.Operator{
				ID:     s.OperatorID,
				PubKey: s.PubKeyBytes,
			}
			if err := spec.ValidateReshareMessage(&reshareMsg.SignedReshare.Reshare, op, reshareMsg.Proofs[i]); err != nil {
				return nil, nil, err
			}
			secretShare, err := crypto.GetSecretShareFromProofs(reshareMsg.Proofs[i], s.PrivateKey, s.OperatorID)
			if err != nil {
				return nil, nil, err
			}
			if secretShare == nil {
				return nil, nil, fmt.Errorf("cant decrypt incoming private share")
			}
			owner.SecretShare = &kyber_dkg.DistKeyShare{
				Commits: commits,
				Share:   secretShare,
			}
			suite := kyber_bls12381.NewBLS12381Suite()
			valPK, err := crypto.ResultToValidatorPK(owner.SecretShare, suite.G1().(kyber_dkg.Suite))
			if err != nil {
				return nil, nil, err
			}
			if !bytes.Equal(valPK.Serialize(), reshareMsg.SignedReshare.Reshare.ValidatorPubKey) {
				return nil, nil, fmt.Errorf("validator pub key recovered from proofs not equal validator pub key at reshare msg")
			}
			secretKeyBLS, err := crypto.ResultToShareSecretKey(owner.SecretShare)
			if err != nil {
				return nil, nil, fmt.Errorf("failed to get BLS partial secret key share: %w", err)
			}
			if !bytes.Equal(secretKeyBLS.GetPublicKey().Serialize(), reshareMsg.Proofs[i].Proof.SharePubKey) {
				return nil, nil, fmt.Errorf("share pub key recovered from proofs not equal share pub key at reshare msg")
			}
			s.Logger.Info("Successfully recovered secret share from proofs")
		}
	}
	resp, err := owner.Reshare(reqID, &reshareMsg.SignedReshare.Reshare, commits)
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
	return spec_crypto.SignRSA(s.PrivateKey, msg)
}

// Encrypt with RSA public key private DKG share key
func (s *Switch) Encrypt(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, msg)
}

// Decrypt with RSA private key private DKG share key
func (s *Switch) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsaencryption.DecodeKey(s.PrivateKey, ciphertext)
}

// NewSwitch creates a new Switch
func NewSwitch(pv *rsa.PrivateKey, logger *zap.Logger, ver, pkBytes []byte, id uint64, ethClient eip1271.ETHClient) *Switch {
	return &Switch{
		Logger:           logger,
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[InstanceID]time.Time, MaxInstances),
		Instances:        make(map[InstanceID]Instance, MaxInstances),
		PrivateKey:       pv,
		Version:          ver,
		PubKeyBytes:      pkBytes,
		OperatorID:       id,
		EthClient:        ethClient,
	}
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
	inst, resp, err := s.CreateInitInstance(reqID, init, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("init: failed to create instance: %s", err.Error())
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
	// check that we received enough messages from other operator participants
	ops, err := inst.CheckIncomingOperators(st.Messages)
	if err != nil {
		return nil, err
	}
	var incOperators []*spec.Operator
	for _, op := range ops {
		incOperators = append(incOperators, op)
	}
	incOperators = spec.OrderOperators(incOperators)
	if !spec.UniqueAndOrderedOperators(incOperators) {
		return nil, fmt.Errorf("operators at incoming messages are not unique")
	}
	for _, ts := range st.Messages {
		err = inst.Process(ts, incOperators)
		if err != nil {
			return nil, fmt.Errorf("process message: failed to process dkg message: %s", err.Error())
		}
	}
	resp := inst.ReadResponse()

	return resp, nil
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

func (s *Switch) Pong() ([]byte, error) {
	pong := &wire.Pong{
		ID:     s.OperatorID,
		PubKey: s.PubKeyBytes,
	}
	return s.MarshallAndSign(pong, wire.PongMessageType, s.OperatorID, [24]byte{})
}

func (s *Switch) SaveResultData(incMsg *wire.SignedTransport, outputPath string) error {
	resData := &wire.ResultData{}
	err := resData.UnmarshalSSZ(incMsg.Message.Data)
	if err != nil {
		return err
	}
	_, err = s.VerifyIncomingMessage(incMsg)
	if err != nil {
		return err
	}
	// Assuming depJson, ksJson, and proofs can be singular instances based on your logic
	var depJson *wire.DepositDataCLI
	if len(resData.DepositData) != 0 {
		err = json.Unmarshal(resData.DepositData, &depJson)
		if err != nil {
			return err
		}
	}
	var ksJson *wire.KeySharesCLI
	err = json.Unmarshal(resData.KeysharesData, &ksJson)
	if err != nil {
		return err
	}
	var proof []*wire.SignedProof
	err = json.Unmarshal(resData.Proofs, &proof)
	if err != nil {
		return err
	}
	// Save results.
	depositDataArr := []*wire.DepositDataCLI{depJson}
	keySharesArr := []*wire.KeySharesCLI{ksJson}
	proofsArr := [][]*wire.SignedProof{proof}
	withdrawCreds, err := hex.DecodeString(depJson.WithdrawalCredentials)
	if err != nil {
		return fmt.Errorf("failed to decode withdrawal credentials: %s", err.Error())
	}
	withdrawPrefix, withdrawAddress := crypto.ParseWithdrawalCredentials(withdrawCreds)
	if withdrawPrefix != spec_crypto.ETH1WithdrawalPrefixByte {
		return fmt.Errorf("invalid withdrawal prefix: %x", withdrawPrefix)
	}
	return cli_utils.WriteResults(
		s.Logger,
		depositDataArr,
		keySharesArr,
		proofsArr,
		true,
		1,
		eth_common.HexToAddress(keySharesArr[0].Shares[0].ShareData.OwnerAddress),
		keySharesArr[0].Shares[0].ShareData.OwnerNonce,
		eth_common.BytesToAddress(withdrawAddress),
		outputPath,
	)
}

func (s *Switch) VerifyIncomingMessage(incMsg *wire.SignedTransport) (uint64, error) {
	if incMsg.Message.Type != wire.ResultMessageType {
		return 0, fmt.Errorf("wrong message type %s expected %s", incMsg.Message.Type, wire.ResultMessageType)
	}

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

	operatorID, err := spec.OperatorIDByPubKey(resData.Operators, s.PubKeyBytes)
	if err != nil {
		return 0, err
	}
	return operatorID, nil
}

// InitInstance creates a LocalOwner instance and DKG public key message (Exchange)
func (s *Switch) ResignInstance(reqID [24]byte, resignMsg *wire.Transport, initiatorPub, initiatorSignature []byte) ([]byte, error) {
	if !bytes.Equal(resignMsg.Version, s.Version) {
		return nil, fmt.Errorf("wrong version: remote %s local %s", resignMsg.Version, s.Version)
	}
	s.Logger.Info("🚀 Initializing Resigning instance")
	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("resign: failed parse initiator public key: %s", err.Error())
	}
	marshalledWireMsg, err := resignMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("resign: failed to marshal transport message: %s", err.Error())
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("resign: initiator signature isn't valid: %s", err.Error())
	}
	resign := &wire.ResignMessage{}
	if err := resign.UnmarshalSSZ(resignMsg.Data); err != nil {
		return nil, fmt.Errorf("resign: failed to unmarshal init message: %s", err.Error())
	}
	s.Logger.Info("✅ resign message signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))
	if err := s.validateInstances(reqID); err != nil {
		return nil, err
	}
	s.Logger.Info("Incoming resign request fields",
		zap.String("network", hex.EncodeToString(resign.SignedResign.Resign.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(resign.SignedResign.Resign.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(resign.SignedResign.Resign.Owner[:])),
		zap.Uint64("nonce", resign.SignedResign.Resign.Nonce))
	for _, proof := range resign.Proofs {
		s.Logger.Info("Loaded proof",
			zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
			zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
			zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
			zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
			zap.String("Signature", hex.EncodeToString(proof.Signature)))
	}
	// verify EIP1271 signature
	if err := spec_crypto.VerifySignedMessageByOwner(
		s.EthClient,
		resign.SignedResign.Resign.Owner,
		&resign.SignedResign.Resign,
		resign.SignedResign.Signature,
	); err != nil {
		return nil, err
	}
	s.Logger.Info("✅ resign eip1271 owner signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))
	inst, resp, err := s.CreateResignInstance(reqID, resign, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("resign: failed to create instance: %s", err.Error())
	}
	s.Mtx.Lock()
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

// InitInstance creates a LocalOwner instance and DKG public key message (Exchange)
func (s *Switch) ReshareInstance(reqID [24]byte, reshareMsg *wire.Transport, initiatorPub, initiatorSignature []byte) ([]byte, error) {
	if !bytes.Equal(reshareMsg.Version, s.Version) {
		return nil, fmt.Errorf("wrong version: remote %s local %s", reshareMsg.Version, s.Version)
	}
	// Check that incoming message signature is valid
	initiatorPubKey, err := spec_crypto.ParseRSAPublicKey(initiatorPub)
	if err != nil {
		return nil, fmt.Errorf("resign: failed parse initiator public key: %s", err.Error())
	}
	marshalledWireMsg, err := reshareMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("resign: failed to marshal transport message: %s", err.Error())
	}
	err = spec_crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, initiatorSignature)
	if err != nil {
		return nil, fmt.Errorf("resign: initiator signature isn't valid: %s", err.Error())
	}
	s.Logger.Info("🚀 Creating reshare instance")
	reshare := &wire.ReshareMessage{}
	if err := reshare.UnmarshalSSZ(reshareMsg.Data); err != nil {
		return nil, fmt.Errorf("init: failed to unmarshal init message: %s", err.Error())
	}
	s.Logger.Info("Incoming reshare request fields",
		zap.Any("Old operator IDs", utils.GetOpIDs(reshare.SignedReshare.Reshare.OldOperators)),
		zap.Any("New operator IDs", utils.GetOpIDs(reshare.SignedReshare.Reshare.NewOperators)),
		zap.String("ValidatorPubKey", hex.EncodeToString(reshare.Proofs[0].Proof.ValidatorPubKey)),
		zap.String("network", hex.EncodeToString(reshare.SignedReshare.Reshare.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(reshare.SignedReshare.Reshare.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(reshare.SignedReshare.Reshare.Owner[:])),
		zap.Uint64("nonce", reshare.SignedReshare.Reshare.Nonce),
		zap.String("EIP1271 owner signature", hex.EncodeToString(reshare.SignedReshare.Signature)))
	for _, proof := range reshare.Proofs {
		s.Logger.Info("Reshare proof",
			zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
			zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
			zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
			zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
			zap.String("Signature", hex.EncodeToString(proof.Signature)))
	}
	// verify EIP1271 signature
	if err := spec_crypto.VerifySignedMessageByOwner(
		s.EthClient,
		reshare.SignedReshare.Reshare.Owner,
		&reshare.SignedReshare.Reshare,
		reshare.SignedReshare.Signature,
	); err != nil {
		return nil, err
	}
	s.Logger.Info("✅ reshare eip1271 owner signature is successfully verified", zap.String("from initiator", fmt.Sprintf("%x", initiatorPubKey.N.Bytes())))
	if err := s.validateInstances(reqID); err != nil {
		return nil, err
	}
	inst, resp, err := s.CreateReshareInstance(reqID, reshare, initiatorPubKey)
	if err != nil {
		return nil, fmt.Errorf("reshare: failed to create instance: %s", err.Error())
	}
	s.Mtx.Lock()
	s.Instances[reqID] = inst
	s.InstanceInitTime[reqID] = time.Now()
	s.Mtx.Unlock()
	return resp, nil
}

func (s *Switch) validateInstances(reqID InstanceID) error {
	s.Mtx.Lock()
	l := len(s.Instances)
	if l >= MaxInstances {
		cleaned := s.CleanInstances()
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
