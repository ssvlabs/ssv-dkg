# DKG Spec

# DKG Ceremony

An initiator client will send an init message to all operators

```go
type Init struct {
	// Operators involved in the DKG
	Operators []*Operator `ssz-max:"13"`
	// T is the threshold for signing
	T uint64
	// WithdrawalCredentials for deposit data
	WithdrawalCredentials []byte `ssz-max:"32"`
	// Fork ethereum fork for signing
	Fork [4]byte `ssz-size:"4"`
	// Owner address (registering and resharing the validator)
	Owner [20]byte `ssz-size:"20"`
	// Owner account nonce
	Nonce uint64
}
```

Operators relay DKG specific messages between them using the initiator as their relay. 
A successful DKG ceremony must include all operators specific in the init message, otherwise fail

The initiator ends up with len(Init.Operators) result objects

```go
// Result is the last message in every DKG which marks a specific node's end of process
type Result struct {
    // Operator ID
    OperatorID uint64
    // Operator RSA pubkey
    PubKeyRSA *rsa.PublicKey
    // RequestID for the DKG instance (not used for signing)
    RequestID [24]byte
    // Partial Operator Signature of Deposit data
    DepositPartialSignature []byte
    // SSV owner + nonce signature
    OwnerNoncePartialSignature []byte
    // Signed proof for the ceremony
    SignedProof SignedProof
}
```

SignedProof holds all the information to verify an operator participated in a ceremony and, in later stage, reshare

```go
// Proof for a DKG ceremony
type Proof struct {
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey []byte `ssz-size:"64"`
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare []byte `ssz-max:"8528"` // 656 * 13
	// SharePubKey is the share's BLS pubkey
	SharePubKey []byte `ssz-size:"96"`
	// Owner address
	Owner [20]byte `ssz-size:"20"`
}
```