package dkg

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/sirupsen/logrus"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/board"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	"github.com/bloxapp/ssv-spec/types"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/herumi/bls-eth-go-binary/bls"
)

type Operator struct {
	IP     string
	ID     uint64
	Pubkey *rsa.PublicKey
}

type DKGData struct {
	ReqID  [24]byte
	init   *wire.Init
	Secret kyber.Scalar
}

// Result is the last message in every DKG which marks a specific node's end of process
type Result struct {
	// RequestID for the DKG instance (not used for signing)
	RequestID [24]byte
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare []byte
	// SharePubKey is the share's BLS pubkey
	SharePubKey []byte
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey types.ValidatorPK
	// Partial Operator Signature of Deposit Data
	PartialSignature types.Signature
}

// Encode returns a msg encoded bytes or error
func (msg *Result) Encode() ([]byte, error) {
	return json.Marshal(msg)
}

// Decode returns error if decoding failed
func (msg *Result) Decode(data []byte) error {
	return json.Unmarshal(data, msg)
}

var ErrAlreadyExists = errors.New("duplicate message")

type LocalOwner struct {
	Logger      *logrus.Entry
	startedDKG  chan struct{}
	ID          uint64
	data        *DKGData
	b           *board.Board
	suite       pairing.Suite
	BroadcastF  func([]byte) error
	Exchanges   map[uint64]*wire.Exchange
	outputs     map[uint64]*wire.Output
	OpPrivKey   *rsa.PrivateKey
	SecretShare *bls.SecretKey

	VerifyFunc func(id uint64, msg, sig []byte) error
	SignFunc   func([]byte) ([]byte, error)

	done chan struct{}
}

type OwnerOpts struct {
	Logger     *logrus.Entry
	ID         uint64
	BroadcastF func([]byte) error
	Suite      pairing.Suite
	VerifyFunc func(id uint64, msg, sig []byte) error
	SignFunc   func([]byte) ([]byte, error)
	OpPrivKey  *rsa.PrivateKey
	//Init       *wire.Init
}

func New(opts OwnerOpts) *LocalOwner {
	owner := &LocalOwner{
		Logger:     opts.Logger,
		startedDKG: make(chan struct{}, 1),
		ID:         opts.ID,
		BroadcastF: opts.BroadcastF,
		Exchanges:  make(map[uint64]*wire.Exchange),
		outputs:    make(map[uint64]*wire.Output),
		SignFunc:   opts.SignFunc,
		VerifyFunc: opts.VerifyFunc,
		done:       make(chan struct{}, 1),
		suite:      opts.Suite,
		OpPrivKey:  opts.OpPrivKey,
	}
	return owner
}

func (o *LocalOwner) StartDKG() error {
	o.Logger.Infof("Starting DKG")

	nodes := make([]dkg.Node, 0)
	for id, e := range o.Exchanges {
		p := o.suite.G1().Point()
		if err := p.UnmarshalBinary(e.PK); err != nil {
			return err
		}

		nodes = append(nodes, dkg.Node{
			Index:  dkg.Index(id),
			Public: p,
		})
	}

	// New protocol
	p, err := wire.NewDKGProtocol(&wire.Config{
		Identifier: o.data.ReqID[:],
		Secret:     o.data.Secret,
		Nodes:      nodes,
		Suite:      o.suite,
		T:          int(o.data.init.T),
		Board:      o.b,

		Logger: o.Logger,
	})
	if err != nil {
		return err
	}
	o.Logger.Infof("Protocol secret %d", o.data.Secret.String())
	//i.dkgProtocol = p

	go func(p *dkg.Protocol, postF func(res *dkg.OptionResult)) {
		res := <-p.WaitEnd()
		postF(&res)

	}(p, o.PostDKG)

	close(o.startedDKG)

	return nil
}

func (o *LocalOwner) Broadcast(ts *wire.Transport) error {
	bts, err := ts.MarshalSSZ()
	if err != nil {
		return err
	}
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

	o.Logger.Infof("responding with a signed message, msg:%v", hex.EncodeToString(final))

	return o.BroadcastF(final)
}

func (o *LocalOwner) PostDKG(res *dkg.OptionResult) {
	// TODO: Result consists of the Pivate Share of the distributed key
	o.Logger.Infof("<<<< ---- Post DKG ---- >>>>")
	o.Logger.Infof("DKG PROTOCOL RESULT %v", res.Result)
	// TODO: handle error
	if res.Error != nil {
		o.Logger.Error(res.Error)
		return
	}

	validatorPubKey, err := crypto.ResultsToValidatorPK(res.Result.Key.Commits, o.suite.G1().(dkg.Suite))
	// TODO: handle error
	if err != nil {
		o.Logger.Error(err)
		return
	}

	o.Logger.Infof("Created validator public key %x", validatorPubKey)
	var tsmsg *wire.Transport
	// TODO: store DKG result at instance for now just as global variable
	o.SecretShare, err = crypto.ResultToShareSecretKey(res.Result)
	
	// TODO: handle error
	if err != nil {
		o.Logger.Error(err)
		return
	}
	
	encryptedShare, err := crypto.Encrypt(&o.OpPrivKey.PublicKey, []byte("0x"+o.SecretShare.SerializeToHexStr()))
	// TODO: handle error
	if err != nil {
		o.Logger.Error(err)
		return
	}

	// Collect operators answers as a confirmation of DKG process and prepare deposit data
	signingRoot, _, err := ssvspec_types.GenerateETHDepositData(
		validatorPubKey.Serialize(),
		o.data.init.WithdrawalCredentials,
		ssvspec_types.MainNetwork.ForkVersion(),
		ssvspec_types.DomainDeposit,
	)
	// TODO: handle error
	if err != nil {
		o.Logger.Error(err)
		return
	}
	// Sign a root
	signedRoot := o.SecretShare.SignByte(signingRoot)

	out := Result{
		RequestID: o.data.ReqID,
		EncryptedShare: encryptedShare,
		SharePubKey: o.SecretShare.GetPublicKey().Serialize(),
		ValidatorPubKey: validatorPubKey.Serialize(),
		PartialSignature: signedRoot.Serialize(),
	}
	encodedOutput, err := out.Encode()
	// TODO: handle error
	if err != nil {
		o.Logger.Error(err)
		return
	}
	// TODO: compose output message OR propagate results to server and handle outputs there
	tsmsg = &wire.Transport{
		Type:       wire.OutputMessageType,
		Identifier: o.data.ReqID,
		Data:       encodedOutput,
	}

	o.Broadcast(tsmsg)
	close(o.done)
}

func (o *LocalOwner) Init(reqID [24]byte, init *wire.Init) (*wire.Transport, error) {
	if o.data == nil {
		o.data = &DKGData{}
	}
	o.data.init = init
	o.data.ReqID = reqID
	kyberLogger := logrus.NewEntry(logrus.New())
	kyberLogger = kyberLogger.WithField("reqid", o.data.ReqID)
	o.b = board.NewBoard(
		kyberLogger,
		func(msg *wire.KyberMessage) error {
			kyberLogger.Logger.Infof("Server: broadcasting kyber message")

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
			// todo broadcast signs?
			go func(trsp *wire.Transport) {
				if err := o.Broadcast(trsp); err != nil {
					o.Logger.Errorf("broadcasting failed %v", err)
				}
			}(trsp)

			return nil
		},
	)

	eciesSK, pk := InitSecret(o.suite)
	o.data.Secret = eciesSK
	bts, _, err := CreateExchange(pk)
	if err != nil {
		return nil, err
	}
	//o.Exchanges[o.ID] = raw // TODO: this is probably needed
	return ExchangeWireMessage(bts, reqID), nil
}

func (o *LocalOwner) processDKG(from uint64, msg *wire.Transport) error {
	kyberMsg := &wire.KyberMessage{}
	if err := kyberMsg.UnmarshalSSZ(msg.Data); err != nil {
		return err
	}

	o.Logger.Infof("Server: Recieved kyber msg of type %v, from %v", kyberMsg.Type.String(), from)

	switch kyberMsg.Type {
	case wire.KyberDealBundleMessageType:
		b, err := wire.DecodeDealBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}

		o.Logger.Infof("Server: received deal bundle from %d", from)

		o.b.DealC <- *b

		o.Logger.Infof("Server: gone through deal sending %d", from)

	case wire.KyberResponseBundleMessageType:

		b, err := wire.DecodeResponseBundle(kyberMsg.Data)
		if err != nil {
			return err
		}

		o.Logger.Infof("Server: received response bundle from %d", from)

		o.b.ResponseC <- *b
	case wire.KyberJustificationBundleMessageType:
		b, err := wire.DecodeJustificationBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}

		o.Logger.Infof("Server: received justification bundle from %d", from)

		o.b.JustificationC <- *b
	default:
		return errors.New("unknown kyber message type")
	}
	return nil
}

func (o *LocalOwner) Process(from uint64, st *wire.SignedTransport) error {

	msgbts, err := st.Message.MarshalSSZ()
	if err != nil {
		return err
	}

	if err := o.VerifyFunc(st.Signer, msgbts, st.Signature); err != nil {
		return err
	}

	t := st.Message

	o.Logger.Infof("Server: got msg from type %s, at: %d", t.Type.String(), o.ID)

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

		// TODO: Handle if len(o.Exchanges) != len(o.data.init.Operators)
		if len(o.Exchanges) == len(o.data.init.Operators) {
			if err := o.StartDKG(); err != nil {
				return err
			}
		}
	case wire.KyberMessageType:
		<-o.startedDKG
		return o.processDKG(from, t)
	case wire.OutputMessageType:
		o.Logger.Infof("Got output but not used to")
	default:
		return errors.New("unknown type")
	}

	return nil
}

func InitSecret(suite pairing.Suite) (kyber.Scalar, kyber.Point) {
	eciesSK := suite.G1().Scalar().Pick(random.New())
	pk := suite.G1().Point().Mul(eciesSK, nil)
	return eciesSK, pk
}

func CreateExchange(pk kyber.Point) ([]byte, *wire.Exchange, error) {
	pkByts, err := pk.MarshalBinary()
	if err != nil {
		return nil, nil, err
	}
	exch := wire.Exchange{
		PK: pkByts,
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
