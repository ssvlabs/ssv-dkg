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
		return fmt.Errorf("failed to unmarshal to proofJSON %w", err)
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
	if sp.Proof == nil || sp.Proof.ValidatorPubKey == nil || sp.Proof.EncryptedShare == nil || sp.Proof.SharePubKey == nil || sp.Proof.Owner == [20]byte{0} || sp.Signature == nil {
		return nil, fmt.Errorf("cant marshal json, signed proof json is malformed")
	}
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
	if signedProof.Proof == nil || signedProof.Proof.ValidatorPubKey == nil || signedProof.Proof.EncryptedShare == nil || signedProof.Proof.SharePubKey == nil || signedProof.Proof.Owner == [20]byte{0} || signedProof.Signature == "" {
		return fmt.Errorf("cant unmarshal json, signed proof json is malformed")
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
		return fmt.Errorf("cant decode hex at proof signature %w", err)
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
		return fmt.Errorf("failed to unmarshal operator: %w", err)
	}
	_, err := url.ParseRequestURI(op.Addr)
	if err != nil {
		return fmt.Errorf("invalid operator %d URL %w", op.ID, err)
	}
	pk, err := ParseRSAPublicKey([]byte(op.PubKey))
	if err != nil {
		return fmt.Errorf("invalid operator %d public key %w", op.ID, err)
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

type SignedBulkResign struct {
	ResignMsgs []*spec.Resign
	Signature  []byte
}

type SignedBulkResignJSON struct {
	ResignMsgs []*Resign `json:"ResignMessages"`
	Signature  string    `json:"Signature"`
}

func (br *SignedBulkResign) MarshalJSON() ([]byte, error) {
	resignMsgs := make([]*Resign, len(br.ResignMsgs))
	for i, r := range br.ResignMsgs {
		resignMsgs[i] = NewResignFromSpec(r)
	}
	return json.Marshal(&SignedBulkResignJSON{
		ResignMsgs: resignMsgs,
		Signature:  hex.EncodeToString(br.Signature),
	})
}

func (br *SignedBulkResign) UnmarshalJSON(data []byte) error {
	var dataJson SignedBulkResignJSON
	if err := json.Unmarshal(data, &dataJson); err != nil {
		return err
	}
	br.ResignMsgs = make([]*spec.Resign, len(dataJson.ResignMsgs))
	for i, r := range dataJson.ResignMsgs {
		br.ResignMsgs[i] = r.ToSpecResign()
	}
	sig, err := hex.DecodeString(dataJson.Signature)
	if err != nil {
		return fmt.Errorf("cant decode signature at signed bulk reshare %s", err.Error())
	}
	br.Signature = sig
	return nil
}

func (br *SignedBulkResign) MarshalResignMessagesJSON() ([]byte, error) {
	resignMsgs := make([]*Resign, len(br.ResignMsgs))
	for i, r := range br.ResignMsgs {
		resignMsgs[i] = NewResignFromSpec(r)
	}
	return json.Marshal(resignMsgs)
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
	Amount                uint64 `json:"amount"`
}

func (r *Resign) ToSpecResign() *spec.Resign {
	return &r.Resign
}

func NewResignFromSpec(r *spec.Resign) *Resign {
	return &Resign{*r}
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

type SignedBulkReshare struct {
	ReshareMsgs []*spec.Reshare
	Signature   []byte
}

type SignedBulkReshareJSON struct {
	ReshareMsgs []*Reshare `json:"ReshareMessages"`
	Signature   string     `json:"Signature"`
}

func (br *SignedBulkReshare) MarshalJSON() ([]byte, error) {
	reshareMsgs := make([]*Reshare, len(br.ReshareMsgs))
	for i, r := range br.ReshareMsgs {
		reshareMsgs[i] = NewReshareFromSpec(r)
	}
	return json.Marshal(&SignedBulkReshareJSON{
		ReshareMsgs: reshareMsgs,
		Signature:   hex.EncodeToString(br.Signature),
	})
}

func (br *SignedBulkReshare) UnmarshalJSON(data []byte) error {
	var dataJson SignedBulkReshareJSON
	if err := json.Unmarshal(data, &dataJson); err != nil {
		return err
	}
	br.ReshareMsgs = make([]*spec.Reshare, len(dataJson.ReshareMsgs))
	for i, r := range dataJson.ReshareMsgs {
		br.ReshareMsgs[i] = r.ToSpecReshare()
	}
	sig, err := hex.DecodeString(dataJson.Signature)
	if err != nil {
		return fmt.Errorf("cant decode signature at signed bulk reshare %s", err.Error())
	}
	br.Signature = sig
	return nil
}

func (br *SignedBulkReshare) MarshalReshareMessagesJSON() ([]byte, error) {
	reshareMsgs := make([]*Reshare, len(br.ReshareMsgs))
	for i, r := range br.ReshareMsgs {
		reshareMsgs[i] = NewReshareFromSpec(r)
	}
	return json.Marshal(reshareMsgs)
}

type Reshare struct {
	spec.Reshare
}

func NewReshareFromSpec(r *spec.Reshare) *Reshare {
	return &Reshare{*r}
}

func (r *Reshare) ToSpecReshare() *spec.Reshare {
	return &r.Reshare
}

func (r *Reshare) MarshalJSON() ([]byte, error) {
	// Convert []*spec.Operator to []*Operator for marshaling
	specOldOperators := make([]*Operator, len(r.OldOperators))
	for i, op := range r.OldOperators {
		specOldOperators[i] = NewOperatorFromSpec(*op)
	}
	specNewOperators := make([]*Operator, len(r.NewOperators))
	for i, op := range r.NewOperators {
		specNewOperators[i] = NewOperatorFromSpec(*op)
	}
	return json.Marshal(ReshareJSON{
		ValidatorPubKey:       hex.EncodeToString(r.ValidatorPubKey),
		OldOperators:          specOldOperators,
		NewOperators:          specNewOperators,
		OldT:                  r.OldT,
		NewT:                  r.NewT,
		Fork:                  hex.EncodeToString(r.Fork[:]),
		WithdrawalCredentials: hex.EncodeToString(r.WithdrawalCredentials),
		Owner:                 hex.EncodeToString(r.Owner[:]),
		Nonce:                 r.Nonce,
	})
}

type ReshareJSON struct {
	// ValidatorPubKey public key corresponding to the shared private key
	ValidatorPubKey string `json:"validatorPubKey"`
	// Operators involved in the DKG
	OldOperators []*Operator `json:"oldOperators"`
	// Operators involved in the resharing
	NewOperators []*Operator `json:"newOperators"`
	// OldT is the old threshold for signing
	OldT uint64 `json:"oldT"`
	// NewT is the old threshold for signing
	NewT uint64 `json:"newT"`
	// Fork ethereum fork for signing
	Fork string `json:"fork"`
	// WithdrawalCredentials for deposit data
	WithdrawalCredentials string `json:"withdrawalCredentials"`
	// Owner address
	Owner string `json:"owner"`
	// Owner nonce
	Nonce uint64 `json:"nonce"`
	// Amount in Gwei (https://eips.ethereum.org/EIPS/eip-7251)
	Amount uint64 `json:"amount"`
}

func (r *Reshare) UnmarshalJSON(data []byte) error {
	var resJSON ReshareJSON
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

	r.OldT = resJSON.OldT
	r.NewT = resJSON.NewT

	r.OldOperators = make([]*spec.Operator, len(resJSON.OldOperators))
	for i, op := range resJSON.OldOperators {
		r.OldOperators[i] = op.ToSpecOperator()
	}

	r.NewOperators = make([]*spec.Operator, len(resJSON.NewOperators))
	for i, op := range resJSON.NewOperators {
		r.NewOperators[i] = op.ToSpecOperator()
	}
	return nil
}

type ResignMessageJSON struct {
	Operators []*Operator       `json:"Operators"`
	Resign    ResignJSON        `json:"Resign"`
	Proofs    []signedProofJSON `json:"Proofs"`
}

func (r *ResignMessage) MarshalJSON() ([]byte, error) {
	var result ResignMessageJSON
	specOperators := make([]*Operator, len(r.Operators))
	for i, op := range r.Operators {
		specOperators[i] = NewOperatorFromSpec(*op)
	}
	result.Operators = specOperators
	result.Resign = ResignJSON{
		ValidatorPubKey:       "0x" + hex.EncodeToString(r.Resign.ValidatorPubKey),
		Fork:                  "0x" + hex.EncodeToString(r.Resign.Fork[:]),
		WithdrawalCredentials: "0x" + hex.EncodeToString(r.Resign.WithdrawalCredentials),
		Owner:                 "0x" + hex.EncodeToString(r.Resign.Owner[:]),
		Nonce:                 r.Resign.Nonce,
		Amount:                r.Resign.Amount,
	}
	for _, sp := range r.Proofs {
		if sp.Proof == nil || sp.Proof.ValidatorPubKey == nil || sp.Proof.EncryptedShare == nil || sp.Proof.SharePubKey == nil || sp.Proof.Owner == [20]byte{0} || sp.Signature == nil {
			return nil, fmt.Errorf("cant marshal json, signed proof json is malformed")
		}
		result.Proofs = append(result.Proofs, signedProofJSON{
			Proof: &Proof{spec.Proof{
				ValidatorPubKey: sp.Proof.ValidatorPubKey,
				EncryptedShare:  sp.Proof.EncryptedShare,
				SharePubKey:     sp.Proof.SharePubKey,
				Owner:           sp.Proof.Owner,
			}},
			Signature: hex.EncodeToString(sp.Signature),
		})
	}
	return json.Marshal(result)
}

func (r *ResignMessage) UnmarshalJSON(data []byte) error {
	var resJSON ResignMessageJSON
	if err := json.Unmarshal(data, &resJSON); err != nil {
		return err
	}
	r.Operators = make([]*spec.Operator, len(resJSON.Operators))
	for i, op := range resJSON.Operators {
		r.Operators[i] = op.ToSpecOperator()
	}
	r.Resign = &spec.Resign{}
	val, err := hex.DecodeString(strings.TrimPrefix(resJSON.Resign.ValidatorPubKey, "0x"))
	if err != nil {
		return fmt.Errorf("invalid validator public key %w", err)
	}
	r.Resign.ValidatorPubKey = val
	fork, err := hex.DecodeString(strings.TrimPrefix(resJSON.Resign.Fork, "0x"))
	if err != nil {
		return fmt.Errorf("invalid fork %w", err)
	}
	copy(r.Resign.Fork[:], fork)
	withdrawalCredentials, err := hex.DecodeString(strings.TrimPrefix(resJSON.Resign.WithdrawalCredentials, "0x"))
	if err != nil {
		return fmt.Errorf("invalid withdrawal credentials %w", err)
	}
	r.Resign.WithdrawalCredentials = withdrawalCredentials
	owner, err := hex.DecodeString(strings.TrimPrefix(resJSON.Resign.Owner, "0x"))
	if err != nil {
		return fmt.Errorf("invalid owner %w", err)
	}
	copy(r.Resign.Owner[:], owner)
	r.Resign.Nonce = resJSON.Resign.Nonce
	r.Resign.Amount = resJSON.Resign.Amount
	r.Proofs = make([]*spec.SignedProof, len(resJSON.Proofs))
	for i, sp := range resJSON.Proofs {
		sig, err := hex.DecodeString(sp.Signature)
		if err != nil {
			return fmt.Errorf("cant decode hex at proof signature %w", err)
		}
		r.Proofs[i] = &spec.SignedProof{
			Proof:     &sp.Proof.Proof,
			Signature: sig,
		}
	}
	return nil
}

type ReshareMessageJSON struct {
	Reshare ReshareJSON       `json:"Reshare"`
	Proofs  []signedProofJSON `json:"Proofs"`
}

func (r *ReshareMessage) MarshalJSON() ([]byte, error) {
	var result ReshareMessageJSON
	specOldOperators := make([]*Operator, len(r.Reshare.OldOperators))
	for i, op := range r.Reshare.OldOperators {
		specOldOperators[i] = NewOperatorFromSpec(*op)
	}
	specNewOperators := make([]*Operator, len(r.Reshare.NewOperators))
	for i, op := range r.Reshare.NewOperators {
		specNewOperators[i] = NewOperatorFromSpec(*op)
	}
	result.Reshare = ReshareJSON{
		ValidatorPubKey:       "0x" + hex.EncodeToString(r.Reshare.ValidatorPubKey),
		OldOperators:          specOldOperators,
		NewOperators:          specNewOperators,
		OldT:                  r.Reshare.OldT,
		NewT:                  r.Reshare.NewT,
		Fork:                  "0x" + hex.EncodeToString(r.Reshare.Fork[:]),
		WithdrawalCredentials: "0x" + hex.EncodeToString(r.Reshare.WithdrawalCredentials),
		Owner:                 "0x" + hex.EncodeToString(r.Reshare.Owner[:]),
		Nonce:                 r.Reshare.Nonce,
		Amount:                r.Reshare.Amount,
	}
	for _, sp := range r.Proofs {
		if sp.Proof == nil || sp.Proof.ValidatorPubKey == nil || sp.Proof.EncryptedShare == nil || sp.Proof.SharePubKey == nil || sp.Proof.Owner == [20]byte{0} || sp.Signature == nil {
			return nil, fmt.Errorf("cant marshal json, signed proof json is malformed")
		}
		result.Proofs = append(result.Proofs, signedProofJSON{
			Proof: &Proof{spec.Proof{
				ValidatorPubKey: sp.Proof.ValidatorPubKey,
				EncryptedShare:  sp.Proof.EncryptedShare,
				SharePubKey:     sp.Proof.SharePubKey,
				Owner:           sp.Proof.Owner,
			}},
			Signature: hex.EncodeToString(sp.Signature),
		})
	}
	return json.Marshal(result)
}

func (r *ReshareMessage) UnmarshalJSON(data []byte) error {
	var resJSON ReshareMessageJSON
	if err := json.Unmarshal(data, &resJSON); err != nil {
		return err
	}
	r.Reshare = &spec.Reshare{}
	val, err := hex.DecodeString(strings.TrimPrefix(resJSON.Reshare.ValidatorPubKey, "0x"))
	if err != nil {
		return fmt.Errorf("invalid validator public key %w", err)
	}
	r.Reshare.ValidatorPubKey = val
	fork, err := hex.DecodeString(strings.TrimPrefix(resJSON.Reshare.Fork, "0x"))
	if err != nil {
		return fmt.Errorf("invalid fork %w", err)
	}
	copy(r.Reshare.Fork[:], fork)
	withdrawalCredentials, err := hex.DecodeString(strings.TrimPrefix(resJSON.Reshare.WithdrawalCredentials, "0x"))
	if err != nil {
		return fmt.Errorf("invalid withdrawal credentials %w", err)
	}
	r.Reshare.WithdrawalCredentials = withdrawalCredentials
	owner, err := hex.DecodeString(strings.TrimPrefix(resJSON.Reshare.Owner, "0x"))
	if err != nil {
		return fmt.Errorf("invalid owner %w", err)
	}
	copy(r.Reshare.Owner[:], owner)
	r.Reshare.Nonce = resJSON.Reshare.Nonce
	r.Reshare.Amount = resJSON.Reshare.Amount
	r.Reshare.OldT = resJSON.Reshare.OldT
	r.Reshare.NewT = resJSON.Reshare.NewT
	r.Reshare.OldOperators = make([]*spec.Operator, len(resJSON.Reshare.OldOperators))
	for i, op := range resJSON.Reshare.OldOperators {
		r.Reshare.OldOperators[i] = op.ToSpecOperator()
	}
	r.Reshare.NewOperators = make([]*spec.Operator, len(resJSON.Reshare.NewOperators))
	for i, op := range resJSON.Reshare.NewOperators {
		r.Reshare.NewOperators[i] = op.ToSpecOperator()
	}
	r.Proofs = make([]*spec.SignedProof, len(resJSON.Proofs))
	for i, sp := range resJSON.Proofs {
		sig, err := hex.DecodeString(sp.Signature)
		if err != nil {
			return fmt.Errorf("cant decode hex at proof signature %w", err)
		}
		r.Proofs[i] = &spec.SignedProof{
			Proof:     &sp.Proof.Proof,
			Signature: sig,
		}
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

func LoadJSONFile(file string, v interface{}) error {
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, &v)
}

func LoadProofs(path string) ([][]*spec.SignedProof, error) {
	arrayOfSignedProofs := make([][]*SignedProof, 0)
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, err
	}
	err = json.Unmarshal(data, &arrayOfSignedProofs)
	if err != nil {
		if strings.Contains(err.Error(), "cannot unmarshal object") {
			// probably get only one proof, try to unmarshal it
			var signedProof []*SignedProof
			if err := json.Unmarshal(data, &signedProof); err != nil {
				return nil, err
			}
			arrayOfSignedProofs = make([][]*SignedProof, 0)
			arrayOfSignedProofs = append(arrayOfSignedProofs, signedProof)
		} else {
			return nil, err
		}
	}
	result := make([][]*spec.SignedProof, 0)
	for _, proofs := range arrayOfSignedProofs {
		specSigProofs := make([]*spec.SignedProof, 0)
		for _, proof := range proofs {
			specSigProofs = append(specSigProofs, &spec.SignedProof{Proof: proof.Proof, Signature: proof.Signature})
		}
		result = append(result, specSigProofs)
	}
	return result, nil
}
