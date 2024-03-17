package spec

import (
	"fmt"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
)

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
	if err := VerifySignedReshare(signedReshare); err != nil {
		return nil, err
	}

	if err := ValidateReshareMessage(signedReshare.Reshare, proofs); err != nil {
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

// VerifySignedReshare returns nil if signature over re-share message is valid
func VerifySignedReshare(signedReshare *SignedReshare) error {
	var isEOASignature bool
	if isEOASignature {
		hash, err := signedReshare.Reshare.HashTreeRoot()
		if err != nil {
			return err
		}

		pk, err := eth_crypto.SigToPub(hash[:], signedReshare.Signature)
		if err != nil {
			return err
		}

		address := eth_crypto.PubkeyToAddress(*pk)

		if common.Address(signedReshare.Reshare.Owner).Cmp(address) != 0 {
			return fmt.Errorf("invalid signed reshare signature")
		}
	} else {
		// EIP 1271 signature
		// gnosis implementation https://github.com/safe-global/safe-smart-account/blob/2278f7ccd502878feb5cec21dd6255b82df374b5/contracts/Safe.sol#L265
		// https://github.com/safe-global/safe-smart-account/blob/main/docs/signatures.md
		// ... verify via contract call
	}

	return nil
}
