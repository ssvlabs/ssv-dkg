package wire

import (
	"crypto/rsa"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	spec "github.com/ssvlabs/dkg-spec"
)

type SSZMarshaller interface {
	MarshalSSZ() ([]byte, error)
	UnmarshalSSZ(buf []byte) error
}
type MultipleSignedTransports struct {
	Identifier [24]byte           `ssz-size:"24"` // this is kinda wasteful, maybe take it out of the msgs?
	Messages   []*SignedTransport `ssz-max:"13"`  // max num of operators
	Signature  []byte             `ssz-max:"2048"`
}

type ErrSSZ struct {
	Error []byte `ssz-max:"512"`
}

type TransportType uint64

const (
	InitMessageType TransportType = iota
	KyberMessageType
	ExchangeMessageType
	OutputMessageType
	KyberDealBundleMessageType
	KyberResponseBundleMessageType
	KyberJustificationBundleMessageType
	BlsSignRequestType
	ErrorMessageType
	PingMessageType
	PongMessageType
	ResultMessageType
	ResignMessageType
)

func (t TransportType) String() string {
	switch t {
	case InitMessageType:
		return "InitMessageType"
	case KyberMessageType:
		return "KyberMessageType"
	case ExchangeMessageType:
		return "ExchangeMessageType"
	case OutputMessageType:
		return "OutputMessageType"
	case KyberDealBundleMessageType:
		return "KyberDealBundleMessageType"
	case KyberResponseBundleMessageType:
		return "KyberResponseBundleMessageType"
	case KyberJustificationBundleMessageType:
		return "KyberJustificationBundleMessageType"
	case BlsSignRequestType:
		return "BlsSignRequestType"
	case ErrorMessageType:
		return "ErrorMessageType"
	case PingMessageType:
		return "PingMessageType"
	case PongMessageType:
		return "PongMessageType"
	case ResultMessageType:
		return "ResultMessageType"
	case ResignMessageType:
		return "ResignMessageType"
	default:
		return "no type impl"
	}
}

type Transport struct {
	Type       TransportType
	Identifier [24]byte `ssz-size:"24"`
	Data       []byte   `ssz-max:"8388608"` // 2^23
	Version    []byte   `ssz-max:"128"`
}

type SignedTransport struct {
	Message   *Transport
	Signer    []byte `ssz-max:"2048"`
	Signature []byte `ssz-max:"2048"`
}

type KyberMessage struct {
	Type TransportType
	Data []byte `ssz-max:"4096"`
}

// Exchange contains the session auth/ encryption key for each node
type Exchange struct {
	PK      []byte `ssz-max:"2048"`
	Commits []byte `ssz-max:"2048"`
}

type Ping struct {
	// Operators involved in the DKG
	Operators []*spec.Operator `ssz-max:"13"`
	// Initiator public key
	InitiatorPublicKey []byte `ssz-max:"2048"`
}

type Pong struct {
	ID     uint64
	PubKey []byte `ssz-max:"2048"`
}

type ResultData struct {
	// Operators involved in the DKG
	Operators []*spec.Operator `ssz-max:"13"`
	// Initiator public key
	Identifier    [24]byte `ssz-size:"24"`
	DepositData   []byte   `ssz-max:"8192"`
	KeysharesData []byte   `ssz-max:"32768"`
	Proofs        []byte   `ssz-max:"32768"`
}

// DepositDataCLI  is a deposit structure from the eth2 deposit CLI (https://github.com/ethereum/staking-deposit-cli).
type DepositDataCLI struct {
	PubKey                string      `json:"pubkey"`
	WithdrawalCredentials string      `json:"withdrawal_credentials"`
	Amount                phase0.Gwei `json:"amount"`
	Signature             string      `json:"signature"`
	DepositMessageRoot    string      `json:"deposit_message_root"`
	DepositDataRoot       string      `json:"deposit_data_root"`
	ForkVersion           string      `json:"fork_version"`
	NetworkName           string      `json:"network_name"`
	DepositCliVersion     string      `json:"deposit_cli_version"`
}

// DepositCliVersion is last version accepted by launchpad
const DepositCliVersion = "2.7.0"

// KeyShares structure to create an json file for ssv smart contract
type KeySharesCLI struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	Shares    []*Data   `json:"shares"`
}

// Data structure as a part of KeyShares representing BLS validator public key and information about validators
type Data struct {
	ShareData ShareData `json:"data"`
	Payload   Payload   `json:"payload"`
}

type ShareData struct {
	OwnerNonce   uint64           `json:"ownerNonce"`
	OwnerAddress string           `json:"ownerAddress"`
	PublicKey    string           `json:"publicKey"`
	Operators    []*spec.Operator `json:"operators"`
}

type Payload struct {
	PublicKey   string   `json:"publicKey"`   // validator's public key
	OperatorIDs []uint64 `json:"operatorIds"` // operators IDs
	SharesData  string   `json:"sharesData"`  // encrypted private BLS shares of each operator participating in DKG
}

type PongResult struct {
	IP     string
	Err    error
	Result []byte
}

// Operator structure represents operators info which is public
type OperatorCLI struct {
	Addr   string         // ip:port
	ID     uint64         // operators ID
	PubKey *rsa.PublicKey // operators RSA public key
}

type ResignMessage struct {
	Operators []*spec.Operator `ssz-max:"13"`
	Resign    *spec.Resign
	Proofs    []*spec.SignedProof `ssz-max:"13"`
}