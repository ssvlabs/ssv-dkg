package dkg

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
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
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/spf13/viper"
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
	ReqID  [24]byte
	init   *wire.Init
	Secret kyber.Scalar
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
	ErrorChan   chan error
	ID          uint64
	data        *DKGData
	b           *board.Board
	suite       pairing.Suite
	BroadcastF  func([]byte) error
	Exchanges   map[uint64]*wire.Exchange
	OpPrivKey   *rsa.PrivateKey
	SecretShare *dkg.DistKeyShare

	VerifyFunc func(id uint64, msg, sig []byte) error
	SignFunc   func([]byte) ([]byte, error)

	Owner              common.Address
	Nonce              uint64
	done               chan struct{}
	InitiatorPublicKey *rsa.PublicKey
}

type OwnerOpts struct {
	Logger             *logrus.Entry
	ID                 uint64
	BroadcastF         func([]byte) error
	Suite              pairing.Suite
	VerifyFunc         func(id uint64, msg, sig []byte) error
	SignFunc           func([]byte) ([]byte, error)
	OpPrivKey          *rsa.PrivateKey
	Owner              [20]byte
	Nonce              uint64
	InitiatorPublicKey *rsa.PublicKey
}

func New(opts OwnerOpts) *LocalOwner {
	owner := &LocalOwner{
		Logger:             opts.Logger,
		startedDKG:         make(chan struct{}, 1),
		ErrorChan:          make(chan error, 1),
		ID:                 opts.ID,
		BroadcastF:         opts.BroadcastF,
		Exchanges:          make(map[uint64]*wire.Exchange),
		SignFunc:           opts.SignFunc,
		VerifyFunc:         opts.VerifyFunc,
		done:               make(chan struct{}, 1),
		suite:              opts.Suite,
		OpPrivKey:          opts.OpPrivKey,
		Owner:              opts.Owner,
		Nonce:              opts.Nonce,
		InitiatorPublicKey: opts.InitiatorPublicKey,
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
			Index:  dkg.Index(id - 1),
			Public: p,
		})
	}
	o.Logger.Debugf("Staring DKG with nodes %v", nodes)

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

	go func(p *dkg.Protocol, postF func(res *dkg.OptionResult) error) {
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

	o.Logger.Debugf("responding with a signed message, msg:%v", hex.EncodeToString(final))

	return o.BroadcastF(final)
}

func (o *LocalOwner) PostDKG(res *dkg.OptionResult) error {
	if res.Error != nil {
		o.Logger.Error(res.Error)
		o.broadcastError(res.Error)
		return res.Error
	}
	o.Logger.Infof("DKG ceremony finished successfully")
	// Store result share a instance
	// TODO: store DKG result at instance for now just as global variable
	o.SecretShare = res.Result.Key

	// Get validator BLS public key from result
	validatorPubKey, err := crypto.ResultToValidatorPK(res.Result, o.suite.G1().(dkg.Suite))
	if err != nil {
		o.broadcastError(err)
		return err
	}
	o.Logger.Debugf("Validator public key %x", validatorPubKey.Serialize())

	// Get BLS partial secret key share from DKG
	secretKeyBLS, err := crypto.ResultToShareSecretKey(res.Result)
	if err != nil {
		o.broadcastError(err)
		return err
	}
	// Store secret if requested
	if viper.GetBool("storeShare") {
		type shareStorage struct {
			Index  int    `json:"index"`
			Secret string `json:"secret"`
		}
		data := shareStorage{
			Index:  res.Result.Key.Share.I,
			Secret: secretKeyBLS.SerializeToHexStr(),
		}
		err = utils.WriteJSON("./secret_share_"+hex.EncodeToString(o.data.ReqID[:]), &data)
		if err != nil {
			o.Logger.Errorf("%v", err)
		}
	}

	// Encrypt BLS share for SSV contract
	rawshare := secretKeyBLS.SerializeToHexStr()
	ciphertext, err := rsa.EncryptPKCS1v15(rand.Reader, &o.OpPrivKey.PublicKey, []byte(rawshare))
	if err != nil {
		o.broadcastError(err)
		return errors.New("cant encrypt share")
	}
	// check that we encrypt right
	shareSecretDecrypted := &bls.SecretKey{}
	decryptedSharePrivateKey, err := rsaencryption.DecodeKey(o.OpPrivKey, ciphertext)
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

	o.Logger.Debugf("Encrypted share %x", ciphertext)
	o.Logger.Debugf("Withdrawal Credentials %x", o.data.init.WithdrawalCredentials)
	o.Logger.Debugf("Fork Version %x", o.data.init.Fork)
	o.Logger.Debugf("Domain %x", ssvspec_types.DomainDeposit)

	// Sign root
	depositRootSig, signRoot, err := crypto.SignDepositData(secretKeyBLS, o.data.init.WithdrawalCredentials[:], validatorPubKey, GetNetworkByFork(o.data.init.Fork), MaxEffectiveBalanceInGwei)
	o.Logger.Debugf("Root %x", signRoot)
	// Validate partial signature
	val := depositRootSig.VerifyByte(secretKeyBLS.GetPublicKey(), signRoot)
	if !val {
		o.broadcastError(err)
		return fmt.Errorf("partial deposit root signature isnt valid %x", depositRootSig.Serialize())
	}
	// Sign SSV owner + nonce
	data := []byte(fmt.Sprintf("%s:%d", o.Owner.String(), o.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	o.Logger.Debugf("Owner, Nonce  %x, %d", o.Owner, o.Nonce)
	o.Logger.Debugf("SSV Keccak 256 of Owner + Nonce  %x", hash)
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
	o.Logger.Debugf("SSV owner + nonce signature  %x", sigOwnerNonce.Serialize())
	out := Result{
		RequestID:                  o.data.ReqID,
		EncryptedShare:             ciphertext,
		SharePubKey:                secretKeyBLS.GetPublicKey().Serialize(),
		ValidatorPubKey:            validatorPubKey.Serialize(),
		DepositPartialSignature:    depositRootSig.Serialize(),
		PubKeyRSA:                  &o.OpPrivKey.PublicKey,
		OperatorID:                 o.ID,
		OwnerNoncePartialSignature: sigOwnerNonce.Serialize(),
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
	o.data.init = init
	o.data.ReqID = reqID
	kyberLogger := logrus.NewEntry(logrus.New())
	kyberLogger = kyberLogger.WithField("reqid", o.data.ReqID)
	o.b = board.NewBoard(
		kyberLogger,
		func(msg *wire.KyberMessage) error {
			kyberLogger.Logger.Debugf("server: broadcasting kyber message")

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
	return ExchangeWireMessage(bts, reqID), nil
}

func (o *LocalOwner) processDKG(from uint64, msg *wire.Transport) error {
	kyberMsg := &wire.KyberMessage{}
	if err := kyberMsg.UnmarshalSSZ(msg.Data); err != nil {
		return err
	}

	o.Logger.Debugf("operator: recieved kyber msg of type %v, from %v", kyberMsg.Type.String(), from)

	switch kyberMsg.Type {
	case wire.KyberDealBundleMessageType:
		b, err := wire.DecodeDealBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}

		o.Logger.Debugf("operator: received deal bundle from %d", from)

		o.b.DealC <- *b

		o.Logger.Debugf("operator: gone through deal sending %d", from)

	case wire.KyberResponseBundleMessageType:

		b, err := wire.DecodeResponseBundle(kyberMsg.Data)
		if err != nil {
			return err
		}

		o.Logger.Debugf("operator: received response bundle from %d", from)

		o.b.ResponseC <- *b
	case wire.KyberJustificationBundleMessageType:
		b, err := wire.DecodeJustificationBundle(kyberMsg.Data, o.suite.G1().(dkg.Suite))
		if err != nil {
			return err
		}

		o.Logger.Debugf("operator: received justification bundle from %d", from)

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
	// Verify operator signatures
	if err := o.VerifyFunc(st.Signer, msgbts, st.Signature); err != nil {
		return err
	}
	t := st.Message
	o.Logger.Debugf("operator: got msg from type %s, at: %d", t.Type.String(), o.ID)
	o.Logger.Infof("Successfully verified incoming DKG message type %s: from %d", t.Type.String(), st.Signer)
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

		if len(o.Exchanges) == len(o.data.init.Operators) {
			if err := o.StartDKG(); err != nil {
				return err
			}
		}
	case wire.KyberMessageType:
		<-o.startedDKG
		return o.processDKG(from, t)
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

func (o *LocalOwner) VerifyInitiatorMessage(msg []byte, sig []byte) error {
	pubKey, err := crypto.EncodePublicKey(o.InitiatorPublicKey)
	if err != nil {
		return err
	}
	if err := crypto.VerifyRSA(o.InitiatorPublicKey, msg, sig); err != nil {
		return fmt.Errorf("failed to verify a message from initiator: %x", pubKey)
	}
	o.Logger.Infof("Successfully verified initiator message signature from: %x", sha256.Sum256(o.InitiatorPublicKey.N.Bytes()))
	return nil
}
