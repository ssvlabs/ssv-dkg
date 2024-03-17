package spec

import (
	"bytes"
	"fmt"
	"golang.org/x/exp/maps"
	"sort"
)

// ValidateReshareMessage returns nil if re-share message is valid
func ValidateReshareMessage(
	reshare Reshare,
	proofs map[*Operator]SignedProof,
) error {
	if !UniqueAndOrderedOperators(reshare.OldOperators) {
		return fmt.Errorf("old operators are not unique and ordered")
	}
	if !EqualOperators(reshare.OldOperators, OrderOperators(maps.Keys(proofs))) {
		return fmt.Errorf("missing operator proofs")
	}
	for operator, proof := range proofs {
		if err := ValidateCeremonyProof(reshare.Owner, reshare.ValidatorPubKey, operator, proof); err != nil {
			return err
		}
	}

	if !UniqueAndOrderedOperators(reshare.NewOperators) {
		return fmt.Errorf("new operators are not unique and ordered")
	}
	if EqualOperators(reshare.OldOperators, reshare.NewOperators) {
		return fmt.Errorf("old and new operators are the same")
	}
	if !ValidThresholdSet(reshare.OldT, reshare.OldOperators) {
		return fmt.Errorf("old threshold set is invalid")
	}
	if !ValidThresholdSet(reshare.NewT, reshare.NewOperators) {
		return fmt.Errorf("new threshold set is invalid")
	}

	return nil
}

// EqualOperators returns true if both arrays of operators are equal
func EqualOperators(a, b []*Operator) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if !bytes.Equal(a[i].PubKey, b[i].PubKey) {
			return false
		}
		if a[i].ID != b[i].ID {
			return false
		}
	}
	return true
}

func OrderOperators(in []*Operator) []*Operator {
	sort.Slice(in, func(i, j int) bool {
		return in[i].ID < in[j].ID
	})
	return in
}
