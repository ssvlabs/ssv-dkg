package initiator

import (
	"crypto/rsa"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
)

// Operator structure represents operators info which is public
type Operator struct {
	Addr   string         // ip:port
	ID     uint64         // operators ID
	PubKey *rsa.PublicKey // operators RSA public key
}

// Operators mapping storage for operator structs [ID]operator
type Operators []Operator

func (o Operators) ByID(id uint64) *Operator {
	for _, op := range o {
		if op.ID == id {
			return &op
		}
	}
	return nil
}

func (o Operators) Clone() Operators {
	clone := make(Operators, len(o))
	copy(clone, o)
	return clone
}

type operatorJSON struct {
	Addr   string `json:"ip"`
	ID     uint64 `json:"id"`
	PubKey string `json:"public_key"`
}

func (o Operator) MarshalJSON() ([]byte, error) {
	pk, err := crypto.EncodeRSAPublicKey(o.PubKey)
	if err != nil {
		return nil, err
	}
	return json.Marshal(operatorJSON{
		Addr:   o.Addr,
		ID:     o.ID,
		PubKey: string(pk),
	})
}

func (o *Operator) UnmarshalJSON(data []byte) error {
	var op operatorJSON
	if err := json.Unmarshal(data, &op); err != nil {
		return fmt.Errorf("failed to unmarshal operator: %s", err.Error())
	}
	_, err := url.ParseRequestURI(op.Addr)
	if err != nil {
		return fmt.Errorf("invalid operator URL %s", err.Error())
	}
	pk, err := crypto.ParseRSAPublicKey([]byte(op.PubKey))
	if err != nil {
		return fmt.Errorf("invalid operator public key %s", err.Error())
	}
	*o = Operator{
		Addr:   strings.TrimRight(op.Addr, "/"),
		ID:     op.ID,
		PubKey: pk,
	}
	return nil
}
