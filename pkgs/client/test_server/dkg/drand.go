package dkg

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	"github.com/drand/kyber/util/random"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/board"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
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
	OperatorID uint32
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
	// DepositPartialSignature index
	DepositPartialSignatureIndex uint64
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

	Owner [20]byte
	Nonce uint64
	done  chan struct{}
}

type OwnerOpts struct {
	Logger     *logrus.Entry
	ID         uint64
	BroadcastF func([]byte) error
	Suite      pairing.Suite
	VerifyFunc func(id uint64, msg, sig []byte) error
	SignFunc   func([]byte) ([]byte, error)
	OpPrivKey  *rsa.PrivateKey
	Owner      [20]byte
	Nonce      uint64
}

func New(opts OwnerOpts) *LocalOwner {
	owner := &LocalOwner{
		Logger:     opts.Logger,
		startedDKG: make(chan struct{}, 1),
		ErrorChan:  make(chan error, 1),
		ID:         opts.ID,
		BroadcastF: opts.BroadcastF,
		Exchanges:  make(map[uint64]*wire.Exchange),
		SignFunc:   opts.SignFunc,
		VerifyFunc: opts.VerifyFunc,
		done:       make(chan struct{}, 1),
		suite:      opts.Suite,
		OpPrivKey:  opts.OpPrivKey,
		Owner:      opts.Owner,
		Nonce:      opts.Nonce,
	}
	return owner
}

func (o *LocalOwner) StartDKG(eve bool) error {
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

	go func(p *dkg.Protocol, postF func(res *dkg.OptionResult, eve bool) error, eve bool) {
		res := <-p.WaitEnd()
		postF(&res, eve)
	}(p, o.PostDKG, eve)
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

func (o *LocalOwner) PostDKG(res *dkg.OptionResult, eve bool) error {
	o.Logger.Infof("<<<< ---- DKG Result ---- >>>>")
	o.Logger.Debugf("DKG PROTOCOL RESULT %v", res.Result)
	if res.Error != nil {
		o.Logger.Error(res.Error)
		o.broadcastError(res.Error)
		return res.Error
	}
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
	// Get BLS partial secret key index. We add 1 because DKG share index starts from 0 but BLS aggregation expects it from 1
	secretKeyBLSindex := res.Result.Key.Share.I + 1
	// Encrypt BLS share for SSV contract
	encryptedShare, err := crypto.Encrypt(&o.OpPrivKey.PublicKey, []byte("0x"+secretKeyBLS.GetHexString()))
	if err != nil {
		o.broadcastError(err)
		return err
	}
	o.Logger.Debugf("Encrypted share %x", encryptedShare)
	o.Logger.Debugf("Withdrawal Credentials %x", o.data.init.WithdrawalCredentials)
	o.Logger.Debugf("Fork Version %x", o.data.init.Fork)
	o.Logger.Debugf("Domain %x", ssvspec_types.DomainDeposit)

	// Sign root
	depositRootSig, signRoot, err := SignDepositData(secretKeyBLS, o.data.init.WithdrawalCredentials, validatorPubKey, getNetworkByFork(o.data.init.Fork), MaxEffectiveBalanceInGwei)
	o.Logger.Debugf("Root %x", signRoot)
	o.Logger.Infof("Partial sig %x", depositRootSig.Serialize())
	// Validate partial signature
	val := depositRootSig.VerifyByte(secretKeyBLS.GetPublicKey(), signRoot)
	if !val {
		o.broadcastError(err)
		return fmt.Errorf("partial deposit root signature isnt valid %x", depositRootSig.Serialize())
	}
	// Sign SSV owner + nonce
	data := []byte(fmt.Sprintf("%s:%d", o.Owner, o.Nonce))
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
	if eve {
		depositRootSig.SetHexString("0x87912f24669427628885cf0b70385b94694951626805ff565f4d2a0b74c433a45b279769ff23c23c8dd4ae3625fa06c20df368c0dc24931f3ebe133b3e1fed7d3477c51fa291e61052b0286c7fc453bb5e10346c43eadda9ef1bac8db14acda4")
	}
	out := Result{
		RequestID:                    o.data.ReqID,
		EncryptedShare:               encryptedShare,
		SharePubKey:                  secretKeyBLS.GetPublicKey().Serialize(),
		ValidatorPubKey:              validatorPubKey.Serialize(),
		DepositPartialSignature:      depositRootSig.Serialize(),
		DepositPartialSignatureIndex: uint64(secretKeyBLSindex),
		PubKeyRSA:                    &o.OpPrivKey.PublicKey,
		OperatorID:                   uint32(o.ID),
		OwnerNoncePartialSignature:   sigOwnerNonce.Serialize(),
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

func (o *LocalOwner) Process(from uint64, st *wire.SignedTransport, eve bool) error {

	msgbts, err := st.Message.MarshalSSZ()
	if err != nil {
		return err
	}
	// Verify operator signatures
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

		if len(o.Exchanges) == len(o.data.init.Operators) {
			if err := o.StartDKG(eve); err != nil {
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

func SignDepositData(validationKey *bls.SecretKey, withdrawalPubKey []byte, validatorPublicKey *bls.PublicKey, network eth2_key_manager_core.Network, amount phase0.Gwei) (*bls.Sign, []byte, error) {
	if !IsSupportedDepositNetwork(network) {
		return nil, nil, errors.Errorf("Network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: withdrawalCredentialsHash(withdrawalPubKey),
		Amount:                amount,
	}
	copy(depositMessage.PublicKey[:], validatorPublicKey.Serialize())

	objRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to determine the root hash of deposit data")
	}

	// Compute domain
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to calculate domain")
	}

	signingData := phase0.SigningData{
		ObjectRoot: objRoot,
	}
	copy(signingData.Domain[:], domain[:])

	root, err := signingData.HashTreeRoot()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to determine the root hash of signing container")
	}

	// Sign
	sig := validationKey.SignByte(root[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign the root")
	}
	return sig, root[:], nil
}

// withdrawalCredentialsHash forms a 32 byte hash of the withdrawal public
// address.
//
// The specification is as follows:
//
//	withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX_BYTE
//	withdrawal_credentials[1:] == hash(withdrawal_pubkey)[1:]
//
// where withdrawal_credentials is of type bytes32.
func withdrawalCredentialsHash(withdrawalPubKey []byte) []byte {
	h := util.SHA256(withdrawalPubKey)
	return append([]byte{BLSWithdrawalPrefixByte}, h[1:]...)[:32]
}

func getNetworkByFork(fork [4]byte) eth2_key_manager_core.Network {
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
