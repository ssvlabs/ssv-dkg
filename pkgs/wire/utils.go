package wire

import (
	"bytes"
)

func ByPubKey(pk []byte, ops []*Operator) *Operator {
	for _, op := range ops {
		if bytes.Equal(pk, op.PubKey) {
			return op
		}
	}
	return nil
}
