package initiator

// Proof for a DKG ceremony
type Proof struct {
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey string `json:"validator"`
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare string `json:"encrypted_share"`
	// SharePubKey is the share's BLS pubkey
	SharePubKey string `json:"share_pub"`
	// Owner address
	Owner string `json:"owner"`
}

type SignedProof struct {
	Proof *Proof
	// Signature is an RSA signature over proof
	Signature string `json:"operator_signature"`
}
