package dkg

import (
	"bytes"
	"crypto/rsa"
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/drand/kyber"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	kyber_share "github.com/drand/kyber/share"
	kyber_dkg "github.com/drand/kyber/share/dkg"
	drand_bls "github.com/drand/kyber/sign/bls" //nolint:all //deprecated: use only NewSchemeOnG2 func
	"github.com/drand/kyber/util/random"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/board"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// DKGdata structure to store at LocalOwner information about initial message parameters and secret scalar to be used as input for DKG protocol
type DKGdata struct {
	// Request ID formed by initiator to identify DKG ceremony
	reqID [24]byte
	// initial message from initiator
	init *spec.Init
	// reshare message from initiator
	reshare *spec.Reshare
	// Randomly generated scalar to be used for DKG ceremony
	secret kyber.Scalar
}

// OwnerOpts structure to pass parameters from Switch to LocalOwner structure
type OwnerOpts struct {
	Logger             *zap.Logger
	ID                 uint64
	BroadcastF         func([]byte) error
	Suite              pairing.Suite
	Signer             crypto.Signer
	EncryptFunc        func([]byte) ([]byte, error)
	DecryptFunc        func([]byte) ([]byte, error)
	InitiatorPublicKey *rsa.PublicKey
	OperatorSecretKey  *rsa.PrivateKey
	Owner              [20]byte
	Nonce              uint64
	Version            []byte
}

var ErrAlreadyExists = errors.New("duplicate message")

// LocalOwner as a main structure created for a new DKG initiation ceremony
type LocalOwner struct {
	Logger             *zap.Logger
	startedDKG         chan struct{}
	ID                 uint64
	data               *DKGdata
	board              *board.Board
	Suite              pairing.Suite
	broadcastF         func([]byte) error
	exchanges          map[uint64]*wire.Exchange
	deals              map[uint64]*kyber_dkg.DealBundle
	signer             crypto.Signer
	encryptFunc        func([]byte) ([]byte, error)
	decryptFunc        func([]byte) ([]byte, error)
	SecretShare        *kyber_dkg.DistKeyShare
	InitiatorPublicKey *rsa.PublicKey
	OperatorSecretKey  *rsa.PrivateKey
	done               chan struct{}
	version            []byte
}

// New creates a LocalOwner structure. We create it for each new DKG ceremony.
func New(opts *OwnerOpts) *LocalOwner {
	owner := &LocalOwner{
		Logger:             opts.Logger,
		startedDKG:         make(chan struct{}, 1),
		ID:                 opts.ID,
		broadcastF:         opts.BroadcastF,
		exchanges:          make(map[uint64]*wire.Exchange),
		deals:              make(map[uint64]*kyber_dkg.DealBundle),
		signer:             opts.Signer,
		encryptFunc:        opts.EncryptFunc,
		decryptFunc:        opts.DecryptFunc,
		InitiatorPublicKey: opts.InitiatorPublicKey,
		OperatorSecretKey:  opts.OperatorSecretKey,
		done:               make(chan struct{}, 1),
		Suite:              opts.Suite,
		version:            opts.Version,
	}
	return owner
}

// StartDKG initializes and starts DKG protocol
func (o *LocalOwner) StartDKG() error {
	o.Logger.Info("Starting DKG")
	nodes := make([]kyber_dkg.Node, 0)
	// Create nodes using public points of all operators participating in the protocol
	// Each operator creates a random secret/public points at G1 when initiating new LocalOwner instance
	for id, e := range o.exchanges {
		p := o.Suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}
		nodes = append(nodes, kyber_dkg.Node{
			Index:  kyber_dkg.Index(id - 1),
			Public: p,
		})
	}
	// New protocol
	logger := o.Logger.With(zap.Uint64("ID", o.ID))
	dkgConfig := &kyber_dkg.Config{
		Longterm:  o.data.secret,
		Nonce:     utils.GetNonce(o.data.reqID[:]),
		Suite:     o.Suite.G1().(kyber_dkg.Suite),
		NewNodes:  nodes,
		OldNodes:  nodes, // when initiating dkg we consider the old nodes the new nodes (taken from kyber)
		Threshold: int(o.data.init.T),
		Auth:      drand_bls.NewSchemeOnG2(o.Suite),
	}
	p, err := wire.NewDKGProtocol(dkgConfig, o.board, logger)
	if err != nil {
		return err
	}
	// Wait when the protocol exchanges finish and process the result
	go func(p *kyber_dkg.Protocol, postF func(res *kyber_dkg.OptionResult) error) {
		res := <-p.WaitEnd()
		if err := postF(&res); err != nil {
			o.Logger.Error("Error in PostDKG function", zap.Error(err))
			o.broadcastError(fmt.Errorf("operator ID:%d, err:%w", o.ID, err))
		}
	}(p, o.PostDKG)
	close(o.startedDKG)
	return nil
}

// Function to send signed messages back to initiator
func (o *LocalOwner) Broadcast(ts *wire.Transport) error {
	bts, err := ts.MarshalSSZ()
	if err != nil {
		return err
	}
	// Sign message with RSA private key
	sign, err := o.signer.Sign(bts)
	if err != nil {
		return err
	}
	pub, err := spec_crypto.EncodeRSAPublicKey(&o.OperatorSecretKey.PublicKey)
	if err != nil {
		return err
	}
	signed := &wire.SignedTransport{
		Message:   ts,
		Signer:    pub,
		Signature: sign,
	}

	final, err := signed.MarshalSSZ()
	if err != nil {
		return err
	}

	return o.broadcastF(final)
}

// PostDKG stores the resulting key share, convert it to BLS points acceptable by ETH2
// and creates the Result structure to send back to initiator
func (o *LocalOwner) PostDKG(res *kyber_dkg.OptionResult) error {
	if res.Error != nil {
		return fmt.Errorf("dkg protocol failed: %w", res.Error)
	}
	o.Logger.Info("DKG ceremony finished successfully")
	// Get validator BLS public key from result
	validatorPubKey, err := crypto.ResultToValidatorPK(res.Result.Key, o.Suite.G1().(kyber_dkg.Suite))
	if err != nil {
		return fmt.Errorf("failed to get validator BLS public key: %w", err)
	}
	// Get BLS partial secret key share from DKG
	secretKeyBLS, err := crypto.ResultToShareSecretKey(res.Result.Key)
	if err != nil {
		return fmt.Errorf("failed to get BLS partial secret key share: %w", err)
	}
	result, err := spec.BuildResult(
		o.ID,
		o.data.reqID,
		secretKeyBLS,
		o.OperatorSecretKey,
		validatorPubKey.Serialize(),
		o.data.init.Owner,
		o.data.init.WithdrawalCredentials,
		o.data.init.Fork,
		o.data.init.Nonce,
		phase0.Gwei(o.data.init.Amount),
	)
	if err != nil {
		return fmt.Errorf("failed to encrypt BLS share: %w", err)
	}
	encodedOutput, err := result.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("failed to encode output: %w", err)
	}
	tsMsg := &wire.Transport{
		Type:       wire.OutputMessageType,
		Identifier: o.data.reqID,
		Data:       encodedOutput,
		Version:    o.version,
	}
	if err := o.Broadcast(tsMsg); err != nil {
		return fmt.Errorf("failed to broadcast output in PostDKG: %w", err)
	}
	close(o.done)
	return nil
}

func (o *LocalOwner) PostReshare(res *kyber_dkg.OptionResult) error {
	if res.Error != nil {
		return fmt.Errorf("dkg protocol failed: %w", res.Error)
	}
	o.Logger.Info("DKG resharing ceremony finished successfully")
	// Get BLS partial secret key share from DKG
	secretKeyBLS, err := crypto.ResultToShareSecretKey(res.Result.Key)
	if err != nil {
		return fmt.Errorf("failed to get validator BLS secret key: %w", err)
	}
	result, err := spec.BuildResult(
		o.ID,
		o.data.reqID,
		secretKeyBLS,
		o.OperatorSecretKey,
		o.data.reshare.ValidatorPubKey,
		o.data.reshare.Owner,
		o.data.reshare.WithdrawalCredentials,
		o.data.reshare.Fork,
		o.data.reshare.Nonce,
		phase0.Gwei(o.data.reshare.Amount),
	)
	if err != nil {
		return err
	}
	encodedOutput, err := result.MarshalSSZ()
	if err != nil {
		return err
	}
	tsMsg := &wire.Transport{
		Type:       wire.OutputMessageType,
		Identifier: o.data.reqID,
		Data:       encodedOutput,
		Version:    o.version,
	}
	if err := o.Broadcast(tsMsg); err != nil {
		return fmt.Errorf("failed to broadcast output in PostReshare: %w", err)
	}
	if _, ok := <-o.done; ok {
		close(o.done)
	}
	return nil
}

// Init function creates an interface for DKG (board) which process protocol messages
// Here we randomly create a point at G1 as a DKG public key for the node
func (o *LocalOwner) Init(reqID [24]byte, init *spec.Init) (*wire.Transport, error) {
	o.data = &DKGdata{}
	o.data.init = init
	o.data.reqID = reqID
	kyberLogger := o.Logger.With(zap.String("reqid", fmt.Sprintf("%x", o.data.reqID[:])))
	o.board = board.NewBoard(
		kyberLogger,
		func(msg *wire.KyberMessage) error {
			kyberLogger.Debug("server: broadcasting kyber message")
			byts, err := msg.MarshalSSZ()
			if err != nil {
				return err
			}
			trsp := &wire.Transport{
				Type:       wire.KyberMessageType,
				Identifier: o.data.reqID,
				Data:       byts,
				Version:    o.version,
			}

			// todo not loop with channels
			go func(trsp *wire.Transport) {
				if err := o.Broadcast(trsp); err != nil {
					o.Logger.Error("broadcasting failed", zap.Error(err))
				}
			}(trsp)

			return nil
		},
	)
	// Generate random k scalar (secret) and corresponding public key k*G where G is a G1 generator
	eciesSK, pk := initsecret(o.Suite)
	o.data.secret = eciesSK
	bts, _, err := CreateExchange(pk, nil)
	if err != nil {
		return nil, err
	}
	return &wire.Transport{
		Type:       wire.ExchangeMessageType,
		Identifier: reqID,
		Data:       bts,
		Version:    o.version,
	}, nil
}

// processDKG after receiving a kyber message type at /dkg route
// KyberDealBundleMessageType - message that contains all the deals and the public polynomial from participating party
// KyberResponseBundleMessageType - status for the deals received at deal bundle
// KyberJustificationBundleMessageType - all justifications for each complaint for received deals bundles
func (o *LocalOwner) processDKG(from uint64, msg *wire.Transport) error {
	kyberMsg := &wire.KyberMessage{}
	if err := kyberMsg.UnmarshalSSZ(msg.Data); err != nil {
		return err
	}
	o.Logger.Debug("operator: received kyber msg", zap.String("type", kyberMsg.Type.String()), zap.Uint64("from", from))
	switch kyberMsg.Type {
	case wire.KyberDealBundleMessageType:
		b, err := wire.DecodeDealBundle(kyberMsg.Data, o.Suite.G1().(kyber_dkg.Suite))
		if err != nil {
			return err
		}
		o.Logger.Debug("operator: received deal bundle from", zap.Uint64("ID", from))
		o.board.DealC <- *b
	case wire.KyberResponseBundleMessageType:
		b, err := wire.DecodeResponseBundle(kyberMsg.Data)
		if err != nil {
			return err
		}
		o.Logger.Debug("operator: received response bundle from", zap.Uint64("ID", from))
		o.board.ResponseC <- *b
	case wire.KyberJustificationBundleMessageType:
		b, err := wire.DecodeJustificationBundle(kyberMsg.Data, o.Suite.G1().(kyber_dkg.Suite))
		if err != nil {
			return err
		}
		o.Logger.Debug("operator: received justification bundle from", zap.Uint64("ID", from))
		o.board.JustificationC <- *b
	default:
		return fmt.Errorf("unknown kyber message type")
	}
	return nil
}

// Process processes incoming messages from initiator at /dkg route
func (o *LocalOwner) Process(st *wire.SignedTransport, incOperators []*spec.Operator) error {
	from, err := spec.OperatorIDByPubKey(incOperators, st.Signer)
	if err != nil {
		return fmt.Errorf("cant find operator ID message from: %w", err)
	}
	msgbts, err := st.Message.MarshalSSZ()
	if err != nil {
		return err
	}
	// Verify operator signatures
	pk, err := spec_crypto.ParseRSAPublicKey(st.Signer)
	if err != nil {
		return err
	}
	if err := spec_crypto.VerifyRSA(pk, msgbts, st.Signature); err != nil {
		return err
	}
	o.Logger.Info("✅ Successfully verified incoming DKG", zap.String("message type", st.Message.Type.String()), zap.Uint64("from", from))
	switch st.Message.Type {
	case wire.ExchangeMessageType:
		exchMsg := &wire.Exchange{}
		if err := exchMsg.UnmarshalSSZ(st.Message.Data); err != nil {
			return err
		}
		if _, ok := o.exchanges[from]; ok {
			return fmt.Errorf("error at init exchange message processing: %w", ErrAlreadyExists)
		}
		o.exchanges[from] = exchMsg

		// check if have all participating operators pub keys, then start dkg protocol
		if o.checkOperators() {
			if err := o.StartDKG(); err != nil {
				return err
			}
		}

	case wire.ReshareExchangeMessageType:
		exchMsg := &wire.Exchange{}
		if err := exchMsg.UnmarshalSSZ(st.Message.Data); err != nil {
			return err
		}
		if _, ok := o.exchanges[from]; ok {
			return fmt.Errorf("error at reshare exchange message processing: %w, from %d", ErrAlreadyExists, from)
		}
		o.exchanges[from] = exchMsg
		if len(o.exchanges) == len(incOperators) {
			for _, op := range o.data.reshare.OldOperators {
				if o.ID == op.ID {
					if err := o.StartReshareDKGOldNodes(); err != nil {
						return err
					}
				}
			}
			ops, err := utils.GetDisjointNewOperators(o.data.reshare.OldOperators, o.data.reshare.NewOperators)
			if err != nil {
				return err
			}
			for _, op := range ops {
				if o.ID != op.ID {
					continue
				}
				bundle := &kyber_dkg.DealBundle{}
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
					Identifier: o.data.reqID,
					Data:       byts,
					Version:    o.version,
				}
				if err := o.Broadcast(trsp); err != nil {
					return fmt.Errorf("failed to broadcast ReshareKyberMessage message: %w", err)
				}
			}
		}
	case wire.ReshareKyberMessageType:
		kyberMsg := &wire.ReshareKyberMessage{}
		if err := kyberMsg.UnmarshalSSZ(st.Message.Data); err != nil {
			return err
		}
		b, err := wire.DecodeDealBundle(kyberMsg.Data, o.Suite.G1().(kyber_dkg.Suite))
		if err != nil {
			return err
		}
		if _, ok := o.deals[from]; ok {
			return fmt.Errorf("error at reshare deals message processing: %w", ErrAlreadyExists)
		}
		o.deals[from] = b
		oldNodes, err := utils.GetCommonOldOperators(o.data.reshare.OldOperators, o.data.reshare.NewOperators)
		if err != nil {
			return err
		}
		newNodes, err := utils.GetDisjointNewOperators(o.data.reshare.OldOperators, o.data.reshare.NewOperators)
		if err != nil {
			return err
		}
		if len(o.deals) == len(incOperators) {
			for _, op := range oldNodes {
				if o.ID == op.ID {
					if err := o.PushDealsOldNodes(); err != nil {
						return err
					}
				}
			}
			for _, op := range newNodes {
				if o.ID == op.ID {
					if err := o.StartReshareDKGNewNodes(); err != nil {
						return err
					}
				}
			}
		}
	case wire.KyberMessageType:
		<-o.startedDKG
		return o.processDKG(from, st.Message)
	default:
		return fmt.Errorf("unknown message type: %s", st.Message.Type.String())
	}
	return nil
}

// initsecret generates a random scalar and computes public point k*G where G is a generator of the field
func initsecret(suite pairing.Suite) (kyber.Scalar, kyber.Point) {
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

// broadcastError propagates the error at operator back to initiator
func (o *LocalOwner) broadcastError(err error) {
	errMsgEnc, err := json.Marshal(err.Error())
	if err != nil {
		o.Logger.Error("failed to marshal error message", zap.Error(err))
		return
	}
	errMsg := &wire.Transport{
		Type:       wire.ErrorMessageType,
		Identifier: o.data.reqID,
		Data:       errMsgEnc,
		Version:    o.version,
	}

	if err := o.Broadcast(errMsg); err != nil {
		o.Logger.Error("failed to broadcast error message", zap.Error(err))
	}
	close(o.done)
}

// checkOperators checks that operator received all participating parties DKG public keys
func (o *LocalOwner) checkOperators() bool {
	for _, op := range o.data.init.Operators {
		if o.exchanges[op.ID] == nil {
			return false
		}
	}
	return true
}

// GetDKGNodes returns a slice of DKG node instances used for the protocol
func (o *LocalOwner) GetDKGNodes(ops []*spec.Operator) ([]kyber_dkg.Node, error) {
	nodes := make([]kyber_dkg.Node, 0)
	for _, op := range ops {
		if o.exchanges[op.ID] == nil {
			continue
		}
		e := o.exchanges[op.ID]
		p := o.Suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return nil, err
		}

		nodes = append(nodes, kyber_dkg.Node{
			Index:  kyber_dkg.Index(op.ID - 1),
			Public: p,
		})
	}
	return nodes, nil
}

func (o *LocalOwner) Resign(reqID [24]byte, r *wire.ResignMessage) (*wire.Transport, error) {
	position := -1
	for i, op := range r.Operators {
		if o.ID == op.ID {
			position = i
			break
		}
	}
	if position == -1 {
		return nil, fmt.Errorf("operator not found among resign operators: %d", o.ID)
	}
	if err := spec.ValidateResignMessage(r.Resign, spec.GetOperator(r.Operators, o.ID), r.Proofs[position]); err != nil {
		return nil, fmt.Errorf("failed to validate resign message: %w", err)
	}
	prShare, err := o.decryptFunc(r.Proofs[position].Proof.EncryptedShare)
	if err != nil {
		return nil, fmt.Errorf("failed to decrypt encrypted share: %w", err)
	}
	secretKeyBLS := &bls.SecretKey{}
	err = secretKeyBLS.SetHexString(string(prShare))
	if err != nil {
		return nil, fmt.Errorf("failed to deserialize private share bytes to BLS secret key: %w", err)
	}
	result, err := spec.BuildResult(
		o.ID,
		reqID,
		secretKeyBLS,
		o.OperatorSecretKey,
		r.Proofs[position].Proof.ValidatorPubKey,
		r.Resign.Owner,
		r.Resign.WithdrawalCredentials,
		r.Resign.Fork,
		r.Resign.Nonce,
		phase0.Gwei(r.Resign.Amount),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to build results message: %w", err)
	}
	encodedOutput, err := result.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("failed to encode output: %w", err)
	}
	return &wire.Transport{
		Type:       wire.OutputMessageType,
		Identifier: reqID,
		Data:       encodedOutput,
		Version:    o.version,
	}, nil
}

// InitReshare initiates a resharing owner of dkg protocol
func (o *LocalOwner) Reshare(reqID [24]byte, reshare *spec.Reshare, commitsPoints []kyber.Point) (*wire.Transport, error) {
	// sanity check
	if o.data != nil {
		return nil, fmt.Errorf("data already exist at local instance: %v", o.data)
	}
	o.data = &DKGdata{}
	var commits []byte
	for _, point := range commitsPoints {
		b, _ := point.MarshalBinary()
		commits = append(commits, b...)
	}
	o.data.reshare = reshare
	o.data.reqID = reqID
	kyberLogger := o.Logger.With(zap.String("reqid", fmt.Sprintf("%x", o.data.reqID[:])))
	o.board = board.NewBoard(
		kyberLogger,
		func(msg *wire.KyberMessage) error {
			kyberLogger.Debug("server: broadcasting kyber message")
			byts, err := msg.MarshalSSZ()
			if err != nil {
				return err
			}

			trsp := &wire.Transport{
				Type:       wire.ReshareKyberMessageType,
				Identifier: o.data.reqID,
				Data:       byts,
				Version:    o.version,
			}

			// todo not loop with channels
			go func(trsp *wire.Transport) {
				if err := o.Broadcast(trsp); err != nil {
					o.Logger.Error("broadcasting failed", zap.Error(err))
				}
			}(trsp)

			return nil
		},
	)

	eciesSK, pk := initsecret(o.Suite)
	o.data.secret = eciesSK
	bts, _, err := CreateExchange(pk, commits)
	if err != nil {
		return nil, err
	}
	return &wire.Transport{
		Type:       wire.ReshareExchangeMessageType,
		Identifier: reqID,
		Data:       bts,
		Version:    o.version,
	}, nil
}

func (o *LocalOwner) StartReshareDKGOldNodes() error {
	o.Logger.Info("Starting Resharing DKG ceremony at old nodes")
	NewNodes, err := o.GetDKGNodes(o.data.reshare.NewOperators)
	if err != nil {
		return err
	}
	OldNodes, err := o.GetDKGNodes(o.data.reshare.OldOperators)
	if err != nil {
		return err
	}
	// New protocol
	logger := o.Logger.With(zap.Uint64("ID", o.ID))
	dkgConfig := &kyber_dkg.Config{
		Longterm:     o.data.secret,
		Nonce:        utils.GetNonce(o.data.reqID[:]),
		Suite:        o.Suite.G1().(kyber_dkg.Suite),
		NewNodes:     NewNodes,
		OldNodes:     OldNodes,
		Threshold:    int(o.data.reshare.NewT),
		OldThreshold: int(o.data.reshare.OldT),
		Auth:         drand_bls.NewSchemeOnG2(o.Suite),
		Share:        o.SecretShare,
	}
	p, err := wire.NewDKGProtocol(dkgConfig, o.board, logger)
	if err != nil {
		return err
	}
	go func(p *kyber_dkg.Protocol, postF func(res *kyber_dkg.OptionResult) error) {
		res := <-p.WaitEnd()
		if err := postF(&res); err != nil {
			o.Logger.Error("Error in PostReshare function", zap.Error(err))
			o.broadcastError(fmt.Errorf("operator ID:%d, err:%w", o.ID, err))
		}
	}(p, o.PostReshare)
	close(o.startedDKG)
	return nil
}

func (o *LocalOwner) StartReshareDKGNewNodes() error {
	o.Logger.Info("Starting Resharing DKG ceremony at new nodes")
	NewNodes, err := o.GetDKGNodes(o.data.reshare.NewOperators)
	if err != nil {
		return err
	}
	OldNodes := make([]kyber_dkg.Node, 0)
	var commits []byte
	for _, op := range o.data.reshare.OldOperators {
		if o.exchanges[op.ID] == nil {
			continue
		}
		e := o.exchanges[op.ID]
		if e.Commits == nil {
			return fmt.Errorf("no commits at exchanges")
		}
		commits = e.Commits
		p := o.Suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		OldNodes = append(OldNodes, kyber_dkg.Node{
			Index:  kyber_dkg.Index(op.ID - 1),
			Public: p,
		})
	}
	var coefs []kyber.Point
	coefsBytes := utils.SplitBytes(commits, 48)
	for _, c := range coefsBytes {
		p := o.Suite.G1().Point()
		err := p.UnmarshalBinary(c)
		if err != nil {
			return err
		}
		coefs = append(coefs, p)
	}
	suite := kyber_bls12381.NewBLS12381Suite()
	exp := kyber_share.NewPubPoly(suite.G1().(kyber_dkg.Suite), suite.G1().(kyber_dkg.Suite).Point().Base(), coefs)
	bytsPK, err := exp.Commit().MarshalBinary()
	if err != nil {
		return fmt.Errorf("could not marshal share %w", err)
	}
	if !bytes.Equal(bytsPK, o.data.reshare.ValidatorPubKey) {
		return fmt.Errorf("validator pub key recovered from proofs not equal validator pub key at reshare msg")
	}
	// New protocol
	logger := o.Logger.With(zap.Uint64("ID", o.ID))
	dkgConfig := &kyber_dkg.Config{
		Longterm:     o.data.secret,
		Nonce:        utils.GetNonce(o.data.reqID[:]),
		Suite:        o.Suite.G1().(kyber_dkg.Suite),
		NewNodes:     NewNodes,
		OldNodes:     OldNodes,
		Threshold:    int(o.data.reshare.NewT),
		OldThreshold: int(o.data.reshare.OldT),
		Auth:         drand_bls.NewSchemeOnG2(o.Suite),
		PublicCoeffs: coefs,
	}
	p, err := wire.NewDKGProtocol(dkgConfig, o.board, logger)
	if err != nil {
		return err
	}
	for _, b := range o.deals {
		o.Logger.Info("Pushing deal", zap.Any("Deal", *b))
		o.board.DealC <- *b
	}
	go func(p *kyber_dkg.Protocol, postF func(res *kyber_dkg.OptionResult) error) {
		res := <-p.WaitEnd()
		if err := postF(&res); err != nil {
			o.Logger.Error("Error in PostReshare function", zap.Error(err))
			o.broadcastError(fmt.Errorf("operator ID:%d, err:%w", o.ID, err))
		}
	}(p, o.PostReshare)
	close(o.startedDKG)
	return nil
}

func (o *LocalOwner) PushDealsOldNodes() error {
	for _, b := range o.deals {
		o.board.DealC <- *b
	}
	return nil
}

func (o *LocalOwner) CheckIncomingOperators(msgs []*wire.SignedTransport) (map[uint64]*spec.Operator, error) {
	// sanity check
	if o.data == nil || (o.data.init == nil && o.data.reshare == nil) || (o.data.init != nil && o.data.reshare != nil) {
		return nil, fmt.Errorf("no init or reshare data at instance, or both are present")
	}
	if o.data.init != nil {
		opsAtMsgs := make(map[uint64]*spec.Operator, 0)
		for _, msg := range msgs {
			id, err := spec.OperatorIDByPubKey(o.data.init.Operators, msg.Signer)
			if err != nil {
				return nil, err
			}
			if _, ok := opsAtMsgs[id]; !ok {
				opsAtMsgs[id] = &spec.Operator{ID: id, PubKey: msg.Signer}
			}
		}
		foundOps, err := FindOperatorsAtList(opsAtMsgs, o.data.init.Operators)
		if err != nil {
			return nil, fmt.Errorf("cant find operators at list %w", err)
		}
		if len(foundOps) != len(o.data.init.Operators) {
			return nil, fmt.Errorf("at init all operators should send messages")
		}
		return opsAtMsgs, nil
	}
	if o.data.reshare != nil {
		opsAtMsgs := make(map[uint64]*spec.Operator, 0)
		for _, msg := range msgs {
			var allOps []*spec.Operator
			allOps = append(allOps, o.data.reshare.OldOperators...)
			allOps = append(allOps, o.data.reshare.NewOperators...)
			id, err := spec.OperatorIDByPubKey(allOps, msg.Signer)
			if err != nil {
				return nil, err
			}
			if _, ok := opsAtMsgs[id]; !ok {
				opsAtMsgs[id] = &spec.Operator{ID: id, PubKey: msg.Signer}
			}
		}
		foundOldOps, err := FindOperatorsAtList(opsAtMsgs, o.data.reshare.OldOperators)
		if err != nil {
			return nil, fmt.Errorf("cant find operators at list %w", err)
		}
		// check threshold
		if len(foundOldOps) < int(o.data.reshare.OldT) {
			return nil, fmt.Errorf("less than threshold of old operators at incoming messages: threshold %d, incoming old operator messages %d", o.data.reshare.OldT, len(foundOldOps))
		}
		foundNewOps, err := FindOperatorsAtList(opsAtMsgs, o.data.reshare.NewOperators)
		if err != nil {
			return nil, err
		}
		// check that all new operators sent messages
		if len(foundNewOps) != len(o.data.reshare.NewOperators) {
			return nil, fmt.Errorf("not all new operators at incoming messages: new ops at reshare %d, incoming new operator messages %d", len(o.data.reshare.NewOperators), len(foundNewOps))
		}
		if len(opsAtMsgs) == 0 {
			return nil, fmt.Errorf("no init or reshare operators found at incoming messages")
		}
		return opsAtMsgs, nil
	}
	return nil, nil
}

func FindOperatorsAtList(list map[uint64]*spec.Operator, ops []*spec.Operator) ([]*spec.Operator, error) {
	var found []*spec.Operator
	for _, op := range ops {
		if _, ok := list[op.ID]; ok {
			found = append(found, op)
		}
	}
	if len(found) == 0 {
		return nil, fmt.Errorf("no operators found at incoming list")
	}
	return found, nil
}
