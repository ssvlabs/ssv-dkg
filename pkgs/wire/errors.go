package wire

import (
	"errors"
)

var (
	ErrSSZEncoding = errors.New("failed to ssz unmarshal message: probably an upgrade to latest version needed")
)

// MakeErr creates an error message
func MakeErr(err error) (reterr []byte) {
	rawerr := &ErrSSZ{Error: []byte(err.Error())}
	reterr, err = rawerr.MarshalSSZ()
	if err != nil {
		rawerr = &ErrSSZ{Error: []byte("something went really wrong, failed to ssz encode error. Please check.")}
		reterr, _ = rawerr.MarshalSSZ()
		return reterr
	}
	return reterr
}
