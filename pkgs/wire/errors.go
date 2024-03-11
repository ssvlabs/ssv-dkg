package wire

// MakeErr creates an error message
func MakeErr(err error) (reterr []byte) {
	rawerr := &ErrSSZ{Error: []byte(err.Error())}
	reterr, err = rawerr.MarshalSSZ()
	if err != nil {
		panic(err)
	}
	return reterr
}
