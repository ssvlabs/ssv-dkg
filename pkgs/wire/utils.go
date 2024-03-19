package wire

import (
	"errors"
)

// parseAsError parses the error from an operator
func ParseAsError(msg []byte) (parsedErr, err error) {
	sszerr := &ErrSSZ{}
	err = sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, err
	}
	return errors.New(string(sszerr.Error)), nil
}
