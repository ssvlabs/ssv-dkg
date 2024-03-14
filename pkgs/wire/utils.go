package wire

import (
	"fmt"
)

func FindByID(id uint64, ops []*Operator) (*Operator, error) {
	for _, operator := range ops {
		if operator.ID == id {
			return operator, nil
		}
	}
	return nil, fmt.Errorf("cant find operator by ID")
}
