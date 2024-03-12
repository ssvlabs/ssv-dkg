package spec

import "github.com/bloxapp/ssv-dkg/pkgs/crypto"

func RunDKG(init *Init) ([]*Result, error) {
	if err := ValidateInitMessage(init); err != nil {
		return nil, err
	}

	id := crypto.NewID()

	var results []*Result
	/*
		DKG ceremony ...
	*/

	return results, ValidateResults(
		init.Operators,
		init.WithdrawalCredentials,
		init.Fork,
		init.Owner,
		init.Nonce,
		id,
		results)
}

func RunReshare(
	withdrawalCredentials []byte,
	fork [4]byte,
	signedReshare *SignedReshare,
	proofs map[*Operator]SignedProof,
) ([]*Result, error) {
	if err := ValidateReshareMessage(signedReshare, proofs); err != nil {
		return nil, err
	}

	id := crypto.NewID()

	var results []*Result
	/*
		DKG ceremony ...
	*/

	return results, ValidateResults(
		signedReshare.Reshare.NewOperators,
		withdrawalCredentials,
		fork,
		signedReshare.Reshare.Owner,
		signedReshare.Reshare.Nonce,
		id,
		results)
}
