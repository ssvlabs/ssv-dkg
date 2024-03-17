package spec

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

type Reshare struct {
	// ValidatorPubKey public key corresponding to the shared private key
	ValidatorPubKey []byte `ssz-size:"48"`
	// Operators involved in the DKG
	OldOperators []*Operator `ssz-max:"13"`
	// Operators involved in the resharing
	NewOperators []*Operator `ssz-max:"13"`
	// OldT is the old threshold for signing
	OldT uint64
	// NewT is the old threshold for signing
	NewT uint64
	// Owner address
	Owner [20]byte `ssz-size:"20"`
	// Owner nonce
	Nonce uint64
}

type SignedReshare struct {
	Reshare Reshare
	// Signature is an ECDSA signature over proof
	Signature []byte `ssz-max:"1536"` // 64 * 24
}

// Result is the last message in every DKG which marks a specific node's end of process
type Result struct {
	// Operator ID
	OperatorID uint64
	// RequestID for the DKG instance (not used for signing)
	RequestID [24]byte
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
	// EncryptedShare standard SSV encrypted share
	EncryptedShare []byte `ssz-max:"512"`
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
