package wire

import "errors"

var (
	ErrSSZEncoding = errors.New("failed to ssz unmarshal message: probably an upgrade to latest version needed")
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
