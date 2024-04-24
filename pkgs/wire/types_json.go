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
	"os"
	"path/filepath"
	"strings"

	spec "github.com/ssvlabs/dkg-spec"
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

type Proof struct {
	spec.Proof // Embedding types.Proof for direct field access
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
		return fmt.Errorf("failed to unmarshal to proofJSON %s", err.Error())
	}
	if len(proof.Owner) != 40 {
		return fmt.Errorf("invalid owner length")
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

	copy(p.Owner[:], owner)
	return nil
}

type signedProofJSON struct {
	Proof *Proof `json:"proof"`
	// Signature is an RSA signature over proof
	Signature string `json:"signature"`
}

type SignedProof struct {
	spec.SignedProof // Embedding types.SignedProof for direct field access
}

func (sp *SignedProof) MarshalJSON() ([]byte, error) {
	return json.Marshal(signedProofJSON{
		Proof: &Proof{spec.Proof{
			ValidatorPubKey: sp.Proof.ValidatorPubKey,
			EncryptedShare:  sp.Proof.EncryptedShare,
			SharePubKey:     sp.Proof.SharePubKey,
			Owner:           sp.Proof.Owner,
		}},
		Signature: hex.EncodeToString(sp.Signature),
	})
}

func (sp *SignedProof) UnmarshalJSON(data []byte) error {
	var signedProof signedProofJSON
	if err := json.Unmarshal(data, &signedProof); err != nil {
		return err
	}
	p := &spec.Proof{
		ValidatorPubKey: signedProof.Proof.ValidatorPubKey,
		EncryptedShare:  signedProof.Proof.EncryptedShare,
		SharePubKey:     signedProof.Proof.SharePubKey,
		Owner:           signedProof.Proof.Owner,
	}
	sp.Proof = p
	sig, err := hex.DecodeString(signedProof.Signature)
	if err != nil {
		return fmt.Errorf("cant decode hex at proof signature %s", err.Error())
	}
	sp.Signature = sig
	return err
}

type operatorJSON struct {
	ID     uint64 `json:"id"`
	PubKey string `json:"operatorKey"`
}

type Operator struct {
	spec.Operator // Embedding types.Operator for direct field access
}

func (op *Operator) MarshalJSON() ([]byte, error) {
	return json.Marshal(operatorJSON{
		ID:     op.ID,
		PubKey: string(op.PubKey),
	})
}

func (op *Operator) UnmarshalJSON(data []byte) error {
	operator := &operatorJSON{}
	if err := json.Unmarshal(data, &operator); err != nil {
		return err
	}
	op.ID = operator.ID
	op.PubKey = []byte(operator.PubKey)
	return nil
}

func NewOperatorFromSpec(op spec.Operator) *Operator {
	return &Operator{op}
}

func (op *Operator) ToSpecOperator() *spec.Operator {
	return &op.Operator
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

type ShareDataJson struct {
	OwnerNonce   uint64      `json:"ownerNonce"`
	OwnerAddress string      `json:"ownerAddress"`
	PublicKey    string      `json:"publicKey"`
	Operators    []*Operator `json:"operators"`
}

// Custom MarshalJSON method
func (sd *ShareData) MarshalJSON() ([]byte, error) {
	// Convert []*spec.Operator to []*Operator for marshaling
	specOperators := make([]*Operator, len(sd.Operators))
	for i, op := range sd.Operators {
		specOperators[i] = NewOperatorFromSpec(*op)
	}
	// Create a struct to encode into JSON that uses the spec.Operator type
	return json.Marshal(&ShareDataJson{
		OwnerNonce:   sd.OwnerNonce,
		OwnerAddress: sd.OwnerAddress,
		PublicKey:    sd.PublicKey,
		Operators:    specOperators,
	})
}

// Custom UnmarshalJSON method
func (sd *ShareData) UnmarshalJSON(data []byte) error {
	// Struct to decode from JSON that uses the spec.Operator type
	var dataJson ShareDataJson
	if err := json.Unmarshal(data, &dataJson); err != nil {
		return err
	}
	sd.OwnerAddress = dataJson.OwnerAddress
	sd.OwnerNonce = dataJson.OwnerNonce
	sd.PublicKey = dataJson.PublicKey
	// Convert []*spec.Operator back to []*Operator
	sd.Operators = make([]*spec.Operator, len(dataJson.Operators))
	for i, op := range dataJson.Operators {
		sd.Operators[i] = op.ToSpecOperator()
	}
	return nil
}

type ResingMessageJSON struct {
	Operators []*Operator `json:"operators"`
	Resign    *Resign     `json:"resign"`
	Proofs    []*Proof    `json:"proofs"`
}

type Resign struct {
	spec.Resign
}
type ResignJSON struct {
	ValidatorPubKey       string `json:"validatorPubKey"`
	Fork                  string `json:"fork"`
	WithdrawalCredentials string `json:"withdrawalCredentials"`
	Owner                 string `json:"owner"`
	Nonce                 uint64 `json:"nonce"`
}

func (r *Resign) MarshalJSON() ([]byte, error) {
	return json.Marshal(ResignJSON{
		ValidatorPubKey:       hex.EncodeToString(r.ValidatorPubKey),
		Fork:                  hex.EncodeToString(r.Fork[:]),
		WithdrawalCredentials: hex.EncodeToString(r.WithdrawalCredentials),
		Owner:                 hex.EncodeToString(r.Owner[:]),
		Nonce:                 r.Nonce,
	})
}

func (r *Resign) UnmarshalJSON(data []byte) error {
	var resJSON ResignJSON
	if err := json.Unmarshal(data, &resJSON); err != nil {
		return err
	}
	val, err := hex.DecodeString(resJSON.ValidatorPubKey)
	if err != nil {
		return fmt.Errorf("invalid validator public key %s", err.Error())
	}
	r.ValidatorPubKey = val
	fork, err := hex.DecodeString(resJSON.Fork)
	if err != nil {
		return fmt.Errorf("invalid fork %s", err.Error())
	}
	copy(r.Fork[:], fork)
	withdrawalCredentials, err := hex.DecodeString(resJSON.WithdrawalCredentials)
	if err != nil {
		return fmt.Errorf("invalid withdrawal credentials %s", err.Error())
	}
	r.WithdrawalCredentials = withdrawalCredentials
	owner, err := hex.DecodeString(resJSON.Owner)
	if err != nil {
		return fmt.Errorf("invalid owner %s", err.Error())
	}
	copy(r.Owner[:], owner)
	r.Nonce = resJSON.Nonce
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

func LoadJSONFile(file string, v interface{}) error {
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &v)
}

func ConvertSignedProofsToSpec(wireProofs []*SignedProof) []*spec.SignedProof {
	specProofs := []*spec.SignedProof{}
	for _, proof := range wireProofs {
		specProofs = append(specProofs, &spec.SignedProof{
			Proof:     proof.Proof,
			Signature: proof.Signature,
		})
	}
	return specProofs
}

func LoadProofs(path string) ([][]*SignedProof, error) {
	var arrayOfSignedProofs [][]*SignedProof
	if err := LoadJSONFile(path, &arrayOfSignedProofs); err != nil {
		if strings.Contains(err.Error(), "cannot unmarshal object") {
			// probably get only one proof, try to unmarshal it
			var signedProof []*SignedProof
			if err := LoadJSONFile(path, &signedProof); err != nil {
				return nil, err
			}
			arrayOfSignedProofs = make([][]*SignedProof, 0)
			arrayOfSignedProofs = append(arrayOfSignedProofs, signedProof)
		} else {
			return nil, err
		}
	}
	return arrayOfSignedProofs, nil
}
