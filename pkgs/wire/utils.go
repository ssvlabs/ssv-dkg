package wire

import (
	"fmt"
)

// parseAsError parses the error from an operator
func ParseAsError(msg []byte) (string, error) {
	sszerr := &ErrSSZ{}
	err := sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return "", fmt.Errorf("failed to ssz unmarshal message: probably an upgrade to latest version needed: %w", err)
	}
	return string(sszerr.Error), nil
}
