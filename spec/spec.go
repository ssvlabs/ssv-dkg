package spec

import "github.com/bloxapp/ssv-dkg/pkgs/crypto"

func DKG(init *Init) ([]*Result, error) {
	if err := ValidateInitMessage(init); err != nil {
		return nil, err
	}

	id := crypto.NewID()

	var results []*Result
	/*
		DKG ceremony ...
	*/

	return results, ValidateResults(init, id, results)
}
