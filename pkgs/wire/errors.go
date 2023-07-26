package wire

import (
	"errors"
)

func MakeErr(err error) []byte {
	rawerr := &ErrSSZ{Error: []byte(err.Error())}
	reterr, _ := rawerr.MarshalSSZ()
	return reterr
}

func GetErr(msg []byte) (error, error) {
	msgerr := &ErrSSZ{}
	if err := msgerr.UnmarshalSSZ(msg); err != nil {
		return nil, err
	}
	return errors.New(string(msgerr.Error[:])), nil
}
