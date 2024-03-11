package spec

import (
	"fmt"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"golang.org/x/exp/maps"
)

// ValidateReshareMessage returns nil if re-share message is valid
func ValidateReshareMessage(
	signedReshare *SignedReshare,
	proofs map[*Operator]SignedProof,
) error {
	if !UniqueAndOrderedOperators(signedReshare.Reshare.NewOperators) {
		return fmt.Errorf("operators and not unique and ordered")
	}
	if !EqualOperators(signedReshare.Reshare.OldOperators, maps.Keys(proofs)) {
		return fmt.Errorf("operators and not unique and ordered")
	}
	if !ValidThresholdSet(signedReshare.Reshare.NewT, signedReshare.Reshare.NewOperators) {
		return fmt.Errorf("threshold set is invalid")
	}

	if err := VerifySignedReshare(signedReshare); err != nil {
		return err
	}

	for operator, proof := range proofs {
		if err := ValidateCeremonyProof(signedReshare.Reshare.Owner, operator, proof); err != nil {
			return err
		}
	}
	return nil
}

// VerifySignedReshare returns nil if signature over re-share message is valid
func VerifySignedReshare(signedReshare *SignedReshare) error {
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
	return nil
}
