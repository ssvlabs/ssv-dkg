package spec

import (
	"bytes"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// ValidateInitMessage returns nil if init message is valid
func ValidateInitMessage(init *wire.Init) error {
	if !UniqueAndOrderedOperators(init.Operators) {
		return fmt.Errorf("operators not unique or not ordered")
	}
	if !ValidThresholdSet(init.T, init.Operators) {
		return fmt.Errorf("threshold set is invalid")
	}

	return nil
}

// ValidThresholdSet returns true if the number of operators and threshold is valid
func ValidThresholdSet(t uint64, operators []*wire.Operator) bool {
	if len(operators) == 4 && t == 3 { // 2f+1 = 3
		return true
	}
	if len(operators) == 7 && t == 5 { // 2f+1 = 5
		return true
	}
	if len(operators) == 10 && t == 7 { // 2f+1 = 7
		return true
	}
	if len(operators) == 13 && t == 9 { // 2f+1 = 9
		return true
	}
	return false
}

// UniqueAndOrderedOperators returns true if array of operators are unique and ordered (no duplicate IDs)
func UniqueAndOrderedOperators(operators []*wire.Operator) bool {
	highestID := uint64(0)
	for _, op := range operators {
		if op.ID <= highestID {
			return false
		}
		highestID = op.ID
	}
	return true
}

// EqualOperators returns true if both arrays of operators are equal
func EqualOperators(a, b []*wire.Operator) bool {
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
