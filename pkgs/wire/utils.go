package wire

import (
	"errors"
	"fmt"
)

// parseAsError parses the error from an operator
func ParseAsError(msg []byte) (parsedErr, err error) {
	sszerr := &ErrSSZ{}
	err = sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, fmt.Errorf("failed to ssz unmarshal message: probably an upgrade to latest version needed: %w", err)
	}
	return errors.New(string(sszerr.Error)), nil
}
