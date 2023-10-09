package dkg

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/board"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/bloxapp/ssv/storage/kv"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/spf13/viper"
	"go.uber.org/zap"
)

const (
	// MaxEffectiveBalanceInGwei is the max effective balance
	MaxEffectiveBalanceInGwei phase0.Gwei = 32000000000

	// BLSWithdrawalPrefixByte is the BLS withdrawal prefix
	BLSWithdrawalPrefixByte = byte(0)
)

// IsSupportedDepositNetwork returns true if the given network is supported
var IsSupportedDepositNetwork = func(network eth2_key_manager_core.Network) bool {
	return network == eth2_key_manager_core.PyrmontNetwork || network == eth2_key_manager_core.PraterNetwork || network == eth2_key_manager_core.MainNetwork
}

type Operator struct {
	IP     string
	ID     uint64
	Pubkey *rsa.PublicKey
}

type DKGData struct {
	ReqID   [24]byte
	Init    *wire.Init
	Reshare *wire.Reshare
	Secret  kyber.Scalar
}

// Result is the last message in every DKG which marks a specific node's end of process
type Result struct {
	// Operator ID
	OperatorID uint64
	// Operator RSA pubkey
	PubKeyRSA *rsa.PublicKey
	// RequestID for the DKG instance (not used for signing)
	RequestID [24]byte
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare []byte
	// SharePubKey is the share's BLS pubkey
	SharePubKey []byte
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey []byte
	// Partial Operator Signature of Deposit Data
	DepositPartialSignature []byte
	// SSV owner + nonce signature
	OwnerNoncePartialSignature []byte
	// Public poly commitments
	Commits []byte
}

// Encode returns a msg encoded bytes or error
func (msg *Result) Encode() ([]byte, error) {
	return json.Marshal(msg)
}

// Decode returns error if decoding failed
func (msg *Result) Decode(data []byte) error {
	return json.Unmarshal(data, msg)
}

type PriShare struct {
	I int    `json:"index"`
	V []byte `json:"secret_point"`
}

type DistKeyShare struct {
	Commits []byte   `json:"commits"`
	Share   PriShare `json:"secret_share"`
}

// Encode returns a msg encoded bytes or error
func (msg *DistKeyShare) Encode() ([]byte, error) {
	return json.Marshal(msg)
}

// Decode returns error if decoding failed
func (msg *DistKeyShare) Decode(data []byte) error {
	return json.Unmarshal(data, msg)
}

var ErrAlreadyExists = errors.New("duplicate message")

type LocalOwner struct {
	Logger      *zap.Logger
	startedDKG  chan struct{}
	ErrorChan   chan error
	ID          uint64
	data        *DKGData
	b           *board.Board
	suite       pairing.Suite
	BroadcastF  func([]byte) error
	Exchanges   map[uint64]*wire.Exchange
	Deals       map[uint64]*dkg.DealBundle
	SecretShare *dkg.DistKeyShare
	VerifyFunc  func(id uint64, msg, sig []byte) error
	SignFunc    func([]byte) ([]byte, error)
	EncryptFunc func([]byte) ([]byte, error)
	DecryptFunc func([]byte) ([]byte, error)
	Owner       common.Address
	Nonce       uint64
	done        chan struct{}
	RSAPub      *rsa.PublicKey
	DB          *kv.BadgerDB
}

type OwnerOpts struct {
	Logger      *zap.Logger
	ID          uint64
	BroadcastF  func([]byte) error
	Suite       pairing.Suite
	VerifyFunc  func(id uint64, msg, sig []byte) error
	SignFunc    func([]byte) ([]byte, error)
	EncryptFunc func([]byte) ([]byte, error)
	DecryptFunc func([]byte) ([]byte, error)
	RSAPub      *rsa.PublicKey
	Owner       [20]byte
	Nonce       uint64
	DB          *kv.BadgerDB
	SecretShare *dkg.DistKeyShare
}

func New(opts OwnerOpts) *LocalOwner {
	owner := &LocalOwner{
		Logger:      opts.Logger,
		startedDKG:  make(chan struct{}, 1),
		ErrorChan:   make(chan error, 1),
		ID:          opts.ID,
		BroadcastF:  opts.BroadcastF,
		Exchanges:   make(map[uint64]*wire.Exchange),
		Deals:       make(map[uint64]*dkg.DealBundle),
		SignFunc:    opts.SignFunc,
		VerifyFunc:  opts.VerifyFunc,
		EncryptFunc: opts.EncryptFunc,
		DecryptFunc: opts.DecryptFunc,
		done:        make(chan struct{}, 1),
		suite:       opts.Suite,
		RSAPub:      opts.RSAPub,
		Owner:       opts.Owner,
		Nonce:       opts.Nonce,
		DB:          opts.DB,
	}
	return owner
}

func (o *LocalOwner) StartDKG() error {
	o.Logger.Info("Starting DKG")
	nodes := make([]dkg.Node, 0)
	for id, e := range o.Exchanges {
		p := o.suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		nodes = append(nodes, dkg.Node{
			Index:  dkg.Index(id - 1),
			Public: p,
		})
	}
	o.Logger.Debug("Staring DKG with nodes: ")
	for _, n := range nodes {
		o.Logger.Debug("node: ", zap.String("nodes", n.Public.String()))
	}
	// New protocol
	p, err := wire.NewDKGProtocol(&wire.Config{
		Identifier: o.data.ReqID[:],
		Secret:     o.data.Secret,
		NewNodes:   nodes,
		Suite:      o.suite,
		T:          int(o.data.Init.T),
		Board:      o.b,
		Logger:     o.Logger,
	})
	if err != nil {
		return err
	}

	go func(p *dkg.Protocol, postF func(res *dkg.OptionResult) error) {
		res := <-p.WaitEnd()
		postF(&res)
	}(p, o.PostDKG)
	close(o.startedDKG)
	return nil
}

func (o *LocalOwner) StartReshareDKGOldNodes() error {
	o.Logger.Info("Starting Resharing DKG ceremony at old nodes")
	NewNodes := make([]dkg.Node, 0)
	for _, op := range o.data.Reshare.NewOperators {
		if o.Exchanges[op.ID] == nil {
			return fmt.Errorf("no operator at Exchanges")
		}
		e := o.Exchanges[op.ID]
		p := o.suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		NewNodes = append(NewNodes, dkg.Node{
			Index:  dkg.Index(op.ID - 1),
			Public: p,
		})
	}
	OldNodes := make([]dkg.Node, 0)
	for _, op := range o.data.Reshare.OldOperators {
		if o.Exchanges[op.ID] == nil {
			return fmt.Errorf("no operator at Exchanges")
		}
		e := o.Exchanges[op.ID]
		p := o.suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		OldNodes = append(OldNodes, dkg.Node{
			Index:  dkg.Index(op.ID - 1),
			Public: p,
		})
	}
	o.Logger.Debug("Staring DKG with nodes: ")
	for _, n := range append(OldNodes, NewNodes...) {
		o.Logger.Debug("node: ", zap.String("nodes", n.Public.String()))
	}
	// New protocol
	p, err := wire.NewReshareProtocolOldNodes(&wire.Config{
		Identifier: o.data.ReqID[:],
		Secret:     o.data.Secret,
		OldNodes:   OldNodes,
		NewNodes:   NewNodes,
		Suite:      o.suite,
		T:          int(o.data.Reshare.OldT),
		NewT:       int(o.data.Reshare.NewT),
		Board:      o.b,
		Share:      o.SecretShare,
		Logger:     o.Logger,
	})
	if err != nil {
		return err
	}

	go func(p *dkg.Protocol, postF func(res *dkg.OptionResult) error) {
		res := <-p.WaitEnd()
		postF(&res)
	}(p, o.PostDKG)
	close(o.startedDKG)
	return nil
}

func (o *LocalOwner) StartReshareDKGNewNodes() error {
	o.Logger.Info("Starting Resharing DKG ceremony at new nodes")
	NewNodes := make([]dkg.Node, 0)
	for _, op := range o.data.Reshare.NewOperators {
		if o.Exchanges[op.ID] == nil {
			return fmt.Errorf("no operator at Exchanges")
		}
		e := o.Exchanges[op.ID]
		p := o.suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		NewNodes = append(NewNodes, dkg.Node{
			Index:  dkg.Index(op.ID - 1),
			Public: p,
		})
	}
	OldNodes := make([]dkg.Node, 0)
	var commits []byte
	var coefs []kyber.Point
	for _, op := range o.data.Reshare.OldOperators {
		if o.Exchanges[op.ID] == nil {
			return fmt.Errorf("no operator at Exchanges")
		}
		e := o.Exchanges[op.ID]
		if e.Commits == nil {
			return fmt.Errorf("no commits at Exchanges")
		}
		o.Logger.Debug("Commits at exchange", zap.Uint64("ID", op.ID), zap.Binary("commits", e.Commits))
		commits = e.Commits
		p := o.suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		OldNodes = append(OldNodes, dkg.Node{
			Index:  dkg.Index(op.ID - 1),
			Public: p,
		})
	}
	o.Logger.Debug("Staring resharing DKG with nodes: ")
	for _, n := range append(OldNodes, NewNodes...) {
		o.Logger.Debug("node: ", zap.String("nodes", n.Public.String()))
	}
	coefsBytes := utils.SplitBytes(commits, 48)
	for _, c := range coefsBytes {
		p := o.suite.G1().Point()
		err := p.UnmarshalBinary(c)
		if err != nil {
			return err
		}
		coefs = append(coefs, p)
	}

	// New protocol
	p, err := wire.NewReshareProtocolNewNodes(&wire.Config{
		Identifier:   o.data.ReqID[:],
		Secret:       o.data.Secret,
		OldNodes:     OldNodes,
		NewNodes:     NewNodes,
		Suite:        o.suite,
		T:            int(o.data.Reshare.OldT),
		NewT:         int(o.data.Reshare.NewT),
		Board:        o.b,
		PublicCoeffs: coefs,
		Logger:       o.Logger,
	})
	if err != nil {
		return err
	}
	for _, b := range o.Deals {
		o.b.DealC <- *b
	}
	go func(p *dkg.Protocol, postF func(res *dkg.OptionResult) error) {
		res := <-p.WaitEnd()
		postF(&res)
	}(p, o.PostReshare)
	close(o.startedDKG)
	return nil
}

func (o *LocalOwner) Broadcast(ts *wire.Transport) error {
	bts, err := ts.MarshalSSZ()
	if err != nil {
		return err
	}
	// Sign message with RSA private key
	sign, err := o.SignFunc(bts)
	if err != nil {
		return err
	}

	signed := &wire.SignedTransport{
		Message:   ts,
		Signer:    o.ID,
		Signature: sign,
	}

	final, err := signed.MarshalSSZ()
	if err != nil {
		return err
	}

	return o.BroadcastF(final)
}

func (o *LocalOwner) PostDKG(res *dkg.OptionResult) error {
	if res.Error != nil {
		o.Logger.Error("DKG ceremony returned error: ", zap.Error(res.Error))
		o.broadcastError(res.Error)
		return res.Error
	}
	o.Logger.Info("DKG ceremony finished successfully")
	// Store result share a instance
	o.SecretShare = res.Result.Key
	// encode priv share
	secret := &DistKeyShare{}
	var commits []byte
	for _, point := range o.SecretShare.Commits {
		b, _ := point.MarshalBinary()
		commits = append(commits, b...)
	}
	secret.Commits = commits
	secterPoint, err := o.SecretShare.Share.V.MarshalBinary()
	if err != nil {
		o.broadcastError(err)
		return err
	}
	secret.Share.V = secterPoint
	secret.Share.I = o.SecretShare.Share.I
	bin, err := secret.Encode()
	if err != nil {
		o.broadcastError(err)
		return err
	}
	encBin, err := o.EncryptSecretDB(bin)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	err = o.DB.Set([]byte("secret"), o.data.ReqID[:], encBin)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Get validator BLS public key from result
	validatorPubKey, err := crypto.ResultToValidatorPK(res.Result, o.suite.G1().(dkg.Suite))
	if err != nil {
		o.broadcastError(err)
		return err
	}
	o.Logger.Debug("Validator`s public key %x", zap.String("key", fmt.Sprintf("%x", validatorPubKey.Serialize())))

	// Get BLS partial secret key share from DKG
	secretKeyBLS, err := crypto.ResultToShareSecretKey(res.Result)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Store secret if requested
	if viper.GetBool("storeShare") {
		type shareStorage struct {
			ID     uint64 `json:"ID"`
			Secret string `json:"secret"`
		}
		data := shareStorage{
			ID:     o.ID,
			Secret: hex.EncodeToString(encBin),
		}
		err = utils.WriteJSON("./secret_share_"+hex.EncodeToString(o.data.ReqID[:]), &data)
		if err != nil {
			o.Logger.Error("Cant write secret share to file: ", zap.Error(err))
			o.broadcastError(err)
			return err
		}
	}

	// Encrypt BLS share for SSV contract
	rawshare := secretKeyBLS.SerializeToHexStr()
	ciphertext, err := o.EncryptFunc([]byte(rawshare))
	if err != nil {
		o.broadcastError(err)
		return fmt.Errorf("cant encrypt private share")
	}
	// check that we encrypt correctly
	shareSecretDecrypted := &bls.SecretKey{}
	decryptedSharePrivateKey, err := o.DecryptFunc(ciphertext)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	if err = shareSecretDecrypted.SetHexString(string(decryptedSharePrivateKey)); err != nil {
		o.broadcastError(err)
		return err
	}

	if !bytes.Equal(shareSecretDecrypted.Serialize(), secretKeyBLS.Serialize()) {
		o.broadcastError(err)
		return err
	}

	o.Logger.Debug("Encrypted share", zap.String("share", fmt.Sprintf("%x", ciphertext)))
	o.Logger.Debug("Withdrawal Credentials", zap.String("creds", fmt.Sprintf("%x", o.data.Init.WithdrawalCredentials)))
	o.Logger.Debug("Fork Version", zap.String("v", fmt.Sprintf("%x", o.data.Init.Fork[:])))
	o.Logger.Debug("Domain", zap.String("bytes", fmt.Sprintf("%x", ssvspec_types.DomainDeposit[:])))

	// Sign root
	depositRootSig, signRoot, err := crypto.SignDepositData(secretKeyBLS, o.data.Init.WithdrawalCredentials[:], validatorPubKey, GetNetworkByFork(o.data.Init.Fork), MaxEffectiveBalanceInGwei)
	o.Logger.Debug("Root", zap.String("", fmt.Sprintf("%x", signRoot)))
	// Validate partial signature
	val := depositRootSig.VerifyByte(secretKeyBLS.GetPublicKey(), signRoot)
	if !val {
		o.broadcastError(err)
		return fmt.Errorf("partial deposit root signature is not valid %x", depositRootSig.Serialize())
	}
	// Sign SSV owner + nonce
	data := []byte(fmt.Sprintf("%s:%d", o.Owner.String(), o.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	o.Logger.Debug("Owner, Nonce", zap.String("owner", o.Owner.String()), zap.Uint64("nonce", o.Nonce))
	o.Logger.Debug("SSV Keccak 256 hash of owner + nonce", zap.String("hash", fmt.Sprintf("%x", hash)))
	sigOwnerNonce := secretKeyBLS.SignByte(hash)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Verify partial SSV owner + nonce signature
	val = sigOwnerNonce.VerifyByte(secretKeyBLS.GetPublicKey(), hash)
	if !val {
		o.broadcastError(err)
		return fmt.Errorf("partial owner + nonce signature isnt valid %x", sigOwnerNonce.Serialize())
	}
	out := Result{
		RequestID:                  o.data.ReqID,
		EncryptedShare:             ciphertext,
		SharePubKey:                secretKeyBLS.GetPublicKey().Serialize(),
		ValidatorPubKey:            validatorPubKey.Serialize(),
		DepositPartialSignature:    depositRootSig.Serialize(),
		PubKeyRSA:                  o.RSAPub,
		OperatorID:                 o.ID,
		OwnerNoncePartialSignature: sigOwnerNonce.Serialize(),
		Commits:                    commits,
	}

	encodedOutput, err := out.Encode()
	if err != nil {
		o.broadcastError(err)
		return err
	}

	tsMsg := &wire.Transport{
		Type:       wire.OutputMessageType,
		Identifier: o.data.ReqID,
		Data:       encodedOutput,
	}

	o.Broadcast(tsMsg)
	close(o.done)
	return nil
}

func (o *LocalOwner) PostReshare(res *dkg.OptionResult) error {
	if res.Error != nil {
		o.Logger.Error("DKG ceremony returned error: ", zap.Error(res.Error))
		o.broadcastError(res.Error)
		return res.Error
	}
	o.Logger.Info("DKG resharing ceremony finished successfully")
	// Store result share a instance
	o.SecretShare = res.Result.Key
	// encode priv share
	secret := &DistKeyShare{}
	var commits []byte
	for _, point := range o.SecretShare.Commits {
		b, _ := point.MarshalBinary()
		commits = append(commits, b...)
	}
	secret.Commits = commits
	secterPoint, err := o.SecretShare.Share.V.MarshalBinary()
	if err != nil {
		o.broadcastError(err)
		return err
	}
	secret.Share.V = secterPoint
	secret.Share.I = o.SecretShare.Share.I
	bin, err := secret.Encode()
	if err != nil {
		o.broadcastError(err)
		return err
	}
	encBin, err := o.EncryptSecretDB(bin)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	err = o.DB.Set([]byte("secret"), o.data.ReqID[:], encBin)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Get validator BLS public key from result
	validatorPubKey, err := crypto.ResultToValidatorPK(res.Result, o.suite.G1().(dkg.Suite))
	if err != nil {
		o.broadcastError(err)
		return err
	}
	o.Logger.Debug("Validator`s public key %x", zap.String("key", fmt.Sprintf("%x", validatorPubKey.Serialize())))

	// Get BLS partial secret key share from DKG
	secretKeyBLS, err := crypto.ResultToShareSecretKey(res.Result)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Store secret if requested
	if viper.GetBool("storeShare") {
		type shareStorage struct {
			ID     uint64 `json:"ID"`
			Secret string `json:"secret"`
		}
		data := shareStorage{
			ID:     o.ID,
			Secret: hex.EncodeToString(encBin),
		}
		err = utils.WriteJSON("./secret_share_"+hex.EncodeToString(o.data.ReqID[:]), &data)
		if err != nil {
			o.Logger.Error("Cant write secret share to file: ", zap.Error(err))
			o.broadcastError(err)
			return err
		}
	}

	// Encrypt BLS share for SSV contract
	rawshare := secretKeyBLS.SerializeToHexStr()
	ciphertext, err := o.EncryptFunc([]byte(rawshare))
	if err != nil {
		o.broadcastError(err)
		return fmt.Errorf("cant encrypt private share")
	}
	// check that we encrypt right
	shareSecretDecrypted := &bls.SecretKey{}
	decryptedSharePrivateKey, err := o.DecryptFunc(ciphertext)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	if err = shareSecretDecrypted.SetHexString(string(decryptedSharePrivateKey)); err != nil {
		o.broadcastError(err)
		return err
	}

	if !bytes.Equal(shareSecretDecrypted.Serialize(), secretKeyBLS.Serialize()) {
		o.broadcastError(err)
		return err
	}

	o.Logger.Debug("Encrypted share", zap.String("share", fmt.Sprintf("%x", ciphertext)))

	// Sign SSV owner + nonce
	data := []byte(fmt.Sprintf("%s:%d", o.Owner.String(), o.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	o.Logger.Debug("Owner, Nonce", zap.String("owner", o.Owner.String()), zap.Uint64("nonce", o.Nonce))
	o.Logger.Debug("SSV Keccak 256 hash of owner + nonce", zap.String("hash", fmt.Sprintf("%x", hash)))
	sigOwnerNonce := secretKeyBLS.SignByte(hash)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Verify partial SSV owner + nonce signature
	val := sigOwnerNonce.VerifyByte(secretKeyBLS.GetPublicKey(), hash)
	if !val {
		o.broadcastError(err)
		return fmt.Errorf("partial owner + nonce signature isnt valid %x", sigOwnerNonce.Serialize())
	}
	out := Result{
		RequestID:                  o.data.ReqID,
		EncryptedShare:             ciphertext,
		SharePubKey:                secretKeyBLS.GetPublicKey().Serialize(),
		ValidatorPubKey:            validatorPubKey.Serialize(),
		PubKeyRSA:                  o.RSAPub,
		OperatorID:                 o.ID,
		OwnerNoncePartialSignature: sigOwnerNonce.Serialize(),
		Commits:                    commits,
	}

	encodedOutput, err := out.Encode()
	if err != nil {
		o.broadcastError(err)
		return err
	}

	tsMsg := &wire.Transport{
		Type:       wire.OutputMessageType,
		Identifier: o.data.ReqID,
		Data:       encodedOutput,
	}

	o.Broadcast(tsMsg)
	close(o.done)
	return nil
}

func (o *LocalOwner) Init(reqID [24]byte, init *wire.Init) (*wire.Transport, error) {
	if o.data == nil {
		o.data = &DKGData{}
	}
	o.data.Init = init
	o.data.ReqID = reqID
	kyberLogger := o.Logger.With(zap.String("reqid", fmt.Sprintf("%x", o.data.ReqID[:])))
	o.b = board.NewBoard(
		kyberLogger,
		func(msg *wire.KyberMessage) error {
			kyberLogger.Debug("server: broadcasting kyber message")
			byts, err := msg.MarshalSSZ()
			if err != nil {
				return err
			}

			trsp := &wire.Transport{
				Type:       wire.KyberMessageType,
				Identifier: o.data.ReqID,
				Data:       byts,
			}

			// todo not loop with channels
			go func(trsp *wire.Transport) {
				if err := o.Broadcast(trsp); err != nil {
					o.Logger.Error("broadcasting failed", zap.Error(err))
				}
			}(trsp)

			return nil
		},
		len(o.data.Init.Operators),
	)

	eciesSK, pk := InitSecret(o.suite)
	o.data.Secret = eciesSK
	bts, _, err := CreateExchange(pk, nil)
	if err != nil {
		return nil, err
	}
	return ExchangeWireMessage(bts, reqID), nil
}

func (o *LocalOwner) CreateInstanceReshare(reqID [24]byte, reshare *wire.Reshare, commits []byte) (*wire.Transport, error) {
	if o.data == nil {
		o.data = &DKGData{}
	}
	o.data.Reshare = reshare
	o.data.ReqID = reqID
	kyberLogger := o.Logger.With(zap.String("reqid", fmt.Sprintf("%x", o.data.ReqID[:])))
	o.b = board.NewBoard(
		kyberLogger,
		func(msg *wire.KyberMessage) error {
			kyberLogger.Debug("server: broadcasting kyber message")
			byts, err := msg.MarshalSSZ()
			if err != nil {
				return err
			}

			trsp := &wire.Transport{
				Type:       wire.ReshareKyberMessageType,
				Identifier: o.data.ReqID,
				Data:       byts,
			}

			// todo not loop with channels
			go func(trsp *wire.Transport) {
				if err := o.Broadcast(trsp); err != nil {
					o.Logger.Error("broadcasting failed", zap.Error(err))
				}
			}(trsp)

			return nil
		},
		len(o.data.Reshare.OldOperators),
	)

	eciesSK, pk := InitSecret(o.suite)
	o.data.Secret = eciesSK
	bts, _, err := CreateExchange(pk, commits)
	if err != nil {
		return nil, err
	}
	return ReshareExchangeWireMessage(bts, reqID), nil
}

func (o *LocalOwner) processDKG(from uint64, msg *wire.Transport) error {
	kyberMsg := &wire.KyberMessage{}
	if err := kyberMsg.UnmarshalSSZ(msg.Data); err != nil {
		return err
	}

	o.Logger.Debug(fmt.Sprintf("operator: recieved kyber msg of type %v, from %v", kyberMsg.Type.String(), from))

	switch kyberMsg.Type {
	case wire.KyberDealBundleMessageType:
		b, err := wire.DecodeDealBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}
		o.Logger.Debug("operator: received deal bundle from", zap.Uint64("ID", from))
		o.b.DealC <- *b
	case wire.KyberResponseBundleMessageType:

		b, err := wire.DecodeResponseBundle(kyberMsg.Data)
		if err != nil {
			return err
		}
		o.Logger.Debug("operator: received response bundle from", zap.Uint64("ID", from))
		o.b.ResponseC <- *b
	case wire.KyberJustificationBundleMessageType:
		b, err := wire.DecodeJustificationBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}
		o.Logger.Debug("operator: received justification bundle from", zap.Uint64("ID", from))
		o.b.JustificationC <- *b
	default:
		return fmt.Errorf("unknown kyber message type")
	}
	return nil
}

func (o *LocalOwner) Process(from uint64, st *wire.SignedTransport) error {
	msgbts, err := st.Message.MarshalSSZ()
	if err != nil {
		return err
	}
	// Verify operator signatures
	if err := o.VerifyFunc(st.Signer, msgbts, st.Signature); err != nil {
		return err
	}
	t := st.Message
	o.Logger.Info("✅ Successfully verified incoming DKG", zap.String("message type", t.Type.String()), zap.Uint64("from", st.Signer))
	switch t.Type {
	case wire.ExchangeMessageType:
		exchMsg := &wire.Exchange{}
		if err := exchMsg.UnmarshalSSZ(t.Data); err != nil {
			return err
		}
		if _, ok := o.Exchanges[from]; ok {
			return ErrAlreadyExists
		}

		o.Exchanges[from] = exchMsg

		for _, op := range o.data.Init.Operators {
			if o.Exchanges[op.ID] == nil {
				return nil
			}
		}
		if err := o.StartDKG(); err != nil {
			return err
		}
	case wire.ReshareExchangeMessageType:
		exchMsg := &wire.Exchange{}
		if err := exchMsg.UnmarshalSSZ(t.Data); err != nil {
			return err
		}
		if _, ok := o.Exchanges[from]; ok {
			return ErrAlreadyExists
		}

		o.Exchanges[from] = exchMsg
		allOps := append(o.data.Reshare.OldOperators, o.data.Reshare.NewOperators...)
		for _, op := range allOps {
			if o.Exchanges[op.ID] == nil {
				return nil
			}
		}
		for _, op := range o.data.Reshare.OldOperators {
			if o.ID == op.ID {
				if err := o.StartReshareDKGOldNodes(); err != nil {
					return err
				}
			}
		}
		for _, op := range o.data.Reshare.NewOperators {
			if o.ID == op.ID {
				bundle := &dkg.DealBundle{}
				b, err := wire.EncodeDealBundle(bundle)
				if err != nil {
					return err
				}
				msg := &wire.ReshareKyberMessage{
					Type: wire.KyberDealBundleMessageType,
					Data: b,
				}

				byts, err := msg.MarshalSSZ()
				if err != nil {
					return err
				}
				trsp := &wire.Transport{
					Type:       wire.ReshareKyberMessageType,
					Identifier: o.data.ReqID,
					Data:       byts,
				}
				o.Broadcast(trsp)
			}
		}
	case wire.ReshareKyberMessageType:
		kyberMsg := &wire.ReshareKyberMessage{}
		if err := kyberMsg.UnmarshalSSZ(t.Data); err != nil {
			return err
		}
		b, err := wire.DecodeDealBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}
		if _, ok := o.Deals[from]; ok {
			return ErrAlreadyExists
		}
		if len(b.Deals) != 0 {
			o.Deals[from] = b
		}
		for _, op := range o.data.Reshare.OldOperators {
			if o.Deals[op.ID] == nil {
				return nil
			}
		}
		for _, op := range o.data.Reshare.NewOperators {
			if o.ID == op.ID {
				if err := o.StartReshareDKGNewNodes(); err != nil {
					return err
				}
			}
		}

	case wire.KyberMessageType:
		<-o.startedDKG
		return o.processDKG(from, t)
	default:
		return fmt.Errorf("unknown message type")
	}
	return nil
}

func InitSecret(suite pairing.Suite) (kyber.Scalar, kyber.Point) {
	eciesSK := suite.G1().Scalar().Pick(random.New())
	pk := suite.G1().Point().Mul(eciesSK, nil)
	return eciesSK, pk
}

func CreateExchange(pk kyber.Point, commits []byte) ([]byte, *wire.Exchange, error) {
	pkByts, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	exch := wire.Exchange{
		PK:      pkByts,
		Commits: commits,
	}
	exchByts, err := exch.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}

	return exchByts, &exch, nil
}

func ExchangeWireMessage(exchData []byte, reqID [24]byte) *wire.Transport {
	return &wire.Transport{
		Type:       wire.ExchangeMessageType,
		Identifier: reqID,
		Data:       exchData,
	}
}

func ReshareExchangeWireMessage(exchData []byte, reqID [24]byte) *wire.Transport {
	return &wire.Transport{
		Type:       wire.ReshareExchangeMessageType,
		Identifier: reqID,
		Data:       exchData,
	}
}

func GetNetworkByFork(fork [4]byte) eth2_key_manager_core.Network {
	switch fork {
	case [4]byte{0x00, 0x00, 0x10, 0x20}:
		return eth2_key_manager_core.PraterNetwork
	case [4]byte{0, 0, 0, 0}:
		return eth2_key_manager_core.MainNetwork
	default:
		return eth2_key_manager_core.MainNetwork
	}
}

func (o *LocalOwner) broadcastError(err error) {
	errMsgEnc, _ := json.Marshal(err.Error())
	errMsg := &wire.Transport{
		Type:       wire.ErrorMessageType,
		Identifier: o.data.ReqID,
		Data:       errMsgEnc,
	}

	o.Broadcast(errMsg)
	close(o.done)
}

func (o *LocalOwner) GetLocalOwner() *LocalOwner {
	return o
}

func (o *LocalOwner) EncryptSecretDB(bin []byte) ([]byte, error) {
	// brake to chunks of 256 byte
	chuncks := utils.SplitBytes(bin, 128)
	var encrypted []byte
	for _, chunk := range chuncks {
		encBin, err := o.EncryptFunc(chunk)
		if err != nil {
			return nil, err
		}
		encrypted = append(encrypted, encBin...)
	}
	return encrypted, nil
}
