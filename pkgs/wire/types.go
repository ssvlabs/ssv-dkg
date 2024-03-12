package wire

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

type Operator struct {
	ID     uint64
	PubKey []byte `ssz-max:"2048"`
}

type Init struct {
	// Operators involved in the DKG
	Operators []*Operator `ssz-max:"13"`
	// T is the threshold for signing
	T uint64
	// WithdrawalCredentials for deposit data
	WithdrawalCredentials []byte `ssz-max:"32"`
	// Fork ethereum fork for signing
	Fork [4]byte `ssz-size:"4"`
	// Owner address
	Owner [20]byte `ssz-size:"20"`
	// Owner nonce
	Nonce uint64
}

// Result is the last message in every DKG which marks a specific node's end of process
type Result struct {
	// Operator ID
	OperatorID uint64
	// RequestID for the DKG instance (not used for signing)
	RequestID [24]byte `ssz-size:"24"`
	// Partial Operator Signature of Deposit data
	DepositPartialSignature []byte `ssz-size:"96"`
	// SSV owner + nonce signature
	OwnerNoncePartialSignature []byte `ssz-size:"96"`
	// Signed proof for the ceremony
	SignedProof SignedProof
}

// Proof for a DKG ceremony
type Proof struct {
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey []byte `ssz-size:"48"`
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare []byte `ssz-max:"8528"` // 656 * 13
	// SharePubKey is the share's BLS pubkey
	SharePubKey []byte `ssz-size:"48"`
	// Owner address
	Owner [20]byte `ssz-size:"20"`
}

type SignedProof struct {
	Proof *Proof
	// Signature is an RSA signature over proof
	Signature []byte `ssz-size:"256"`
}

// Exchange contains the session auth/ encryption key for each node
type Exchange struct {
	PK      []byte `ssz-max:"2048"`
	Commits []byte `ssz-max:"2048"`
}

type Ping struct {
	// Operators involved in the DKG
	Operators []*Operator `ssz-max:"13"`
	// Initiator public key
	InitiatorPublicKey []byte `ssz-max:"2048"`
}

type Pong struct {
	PubKey []byte `ssz-max:"2048"`
}

type ResultData struct {
	// Operators involved in the DKG
	Operators []*Operator `ssz-max:"13"`
	// Initiator public key
	Identifier    [24]byte `ssz-size:"24"`
	DepositData   []byte   `ssz-max:"8192"`
	KeysharesData []byte   `ssz-max:"32768"`
}
