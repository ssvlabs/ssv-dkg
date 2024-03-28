package wire

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"net/url"
	"strings"
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
	Proof *Proof `json:"proof"`
	// Signature is an RSA signature over proof
	Signature string `json:"signature"`
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

type operatorJSON struct {
	ID     uint64 `json:"id"`
	PubKey string `json:"operatorKey"`
}

func (op *Operator) MarshalJSON() ([]byte, error) {
	return json.Marshal(operatorJSON{
		ID:     op.ID,
		PubKey: string(op.PubKey),
	})
}

func (op *Operator) UnmarshalJSON(data []byte) error {
	var operator operatorJSON
	if err := json.Unmarshal(data, &operator); err != nil {
		return err
	}
	var err error
	op.ID = operator.ID
	op.PubKey = []byte(operator.PubKey)
	return err
}

// Operators mapping storage for operator structs [ID]operator
type OperatorsCLI []OperatorCLI

func (o OperatorsCLI) ByID(id uint64) *OperatorCLI {
	for _, op := range o {
		if op.ID == id {
			return &op
		}
	}
	return nil
}

func (o OperatorsCLI) ByPubKey(pk *rsa.PublicKey) *OperatorCLI {
	encodedPk, err := EncodeRSAPublicKey(pk)
	if err != nil {
		return nil
	}

	for _, op := range o {
		opPK, err := EncodeRSAPublicKey(op.PubKey)
		if err != nil {
			return nil
		}
		if bytes.Equal(opPK, encodedPk) {
			return &op
		}
	}
	return nil
}

func (o OperatorsCLI) Clone() OperatorsCLI {
	clone := make(OperatorsCLI, len(o))
	copy(clone, o)
	return clone
}

type operatorCLIJSON struct {
	Addr   string `json:"ip"`
	ID     uint64 `json:"id"`
	PubKey string `json:"public_key"`
}

func (o *OperatorCLI) MarshalJSON() ([]byte, error) {
	pk, err := EncodeRSAPublicKey(o.PubKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(operatorCLIJSON{
		Addr:   o.Addr,
		ID:     o.ID,
		PubKey: string(pk),
	})
}

func (o *OperatorCLI) UnmarshalJSON(data []byte) error {
	var op operatorCLIJSON
	if err := json.Unmarshal(data, &op); err != nil {
		return fmt.Errorf("failed to unmarshal operator: %s", err.Error())
	}
	_, err := url.ParseRequestURI(op.Addr)
	if err != nil {
		return fmt.Errorf("invalid operator URL %s", err.Error())
	}
	pk, err := ParseRSAPublicKey([]byte(op.PubKey))
	if err != nil {
		return fmt.Errorf("invalid operator public key %s", err.Error())
	}
	*o = OperatorCLI{
		Addr:   strings.TrimRight(op.Addr, "/"),
		ID:     op.ID,
		PubKey: pk,
	}
	return nil
}

// TODO: duplicate from crypto. Resolve
func ParseRSAPublicKey(pk []byte) (*rsa.PublicKey, error) {
	operatorKeyByte, err := base64.StdEncoding.DecodeString(string(pk))
	if err != nil {
		return nil, err
	}
	pemblock, _ := pem.Decode(operatorKeyByte)
	if pemblock == nil {
		return nil, errors.New("decode PEM block")
	}
	pbkey, err := x509.ParsePKIXPublicKey(pemblock.Bytes)
	if err != nil {
		return nil, err
	}
	return pbkey.(*rsa.PublicKey), nil
}

// TODO: duplicate from crypto. Resolve
func EncodeRSAPublicKey(pk *rsa.PublicKey) ([]byte, error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	pemByte := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pkBytes,
		},
	)
	if pemByte == nil {
		return nil, fmt.Errorf("failed to encode pub key to pem")
	}

	return []byte(base64.StdEncoding.EncodeToString(pemByte)), nil
}
