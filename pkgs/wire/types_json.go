package wire

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
)

// Proof for a DKG ceremony
type proofJSON struct {
	// ValidatorPubKey the resulting public key corresponding to the shared private key
	ValidatorPubKey string `json:"validator"`
	// EncryptedShare standard SSV encrypted shares
	EncryptedShare string `json:"encrypted_share"`
	// SharePubKey is the share's BLS pubkey
	SharePubKey string `json:"share_pub"`
	// Owner address
	Owner string `json:"owner"`
}

func (p *Proof) MarshalJSON() ([]byte, error) {
	return json.Marshal(proofJSON{
		ValidatorPubKey: hex.EncodeToString(p.ValidatorPubKey),
		EncryptedShare:  hex.EncodeToString(p.EncryptedShare),
		SharePubKey:     hex.EncodeToString(p.SharePubKey),
		Owner:           hex.EncodeToString(p.Owner[:]),
	})
}

func (p *Proof) UnmarshalJSON(data []byte) error {
	var proof proofJSON
	if err := json.Unmarshal(data, &proof); err != nil {
		return err
	}
	var err error
	p.ValidatorPubKey, err = hex.DecodeString(proof.ValidatorPubKey)
	if err != nil {
		return err
	}
	p.EncryptedShare, err = hex.DecodeString(proof.EncryptedShare)
	if err != nil {
		return err
	}
	p.SharePubKey, err = hex.DecodeString(proof.SharePubKey)
	if err != nil {
		return err
	}
	owner, err := hex.DecodeString(proof.Owner)
	if err != nil {
		return err
	}
	if len(owner) != 20 {
		return fmt.Errorf("invalid owner length")
	}
	copy(p.Owner[:], owner)
	return nil
}

type signedProofJSON struct {
	Proof *Proof
	// Signature is an RSA signature over proof
	Signature string `json:"operator_signature"`
}

func (sp *SignedProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(signedProofJSON{
		Proof:     sp.Proof,
		Signature: hex.EncodeToString(sp.Signature),
	})
}

func (sp *SignedProof) UnmarshalJSON(data []byte) error {
	var signedProof signedProofJSON
	if err := json.Unmarshal(data, &signedProof); err != nil {
		return err
	}
	var err error
	sp.Proof = signedProof.Proof
	sp.Signature, err = hex.DecodeString(signedProof.Signature)
	return err
}
