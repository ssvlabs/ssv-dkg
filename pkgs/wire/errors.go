package wire

import (
	"errors"
)

// MakeErr creates an error message
func MakeErr(err error) (reterr []byte) {
	rawerr := &ErrSSZ{Error: []byte(err.Error())}
	reterr, err = rawerr.MarshalSSZ()
	if err != nil {
		panic(err)
	}
	return reterr
}

// GetErr extracts an error from a message
func GetErr(msg []byte) (parsedErr, err error) {
	msgerr := &ErrSSZ{}
	if err := msgerr.UnmarshalSSZ(msg); err != nil {
		return nil, err
	}
	return errors.New(string(msgerr.Error)), nil
}
