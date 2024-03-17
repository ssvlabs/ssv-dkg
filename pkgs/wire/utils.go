package wire

import (
	"errors"
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

// parseAsError parses the error from an operator
func ParseAsError(msg []byte) (parsedErr, err error) {
	sszerr := &ErrSSZ{}
	err = sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, err
	}
	return errors.New(string(sszerr.Error)), nil
}
