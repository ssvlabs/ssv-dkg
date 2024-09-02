package utils

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"sort"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
)

var ErrMissingInstance = errors.New("got message to instance that I don't have, send Init first")
var ErrAlreadyExists = errors.New("got init msg for existing instance")
var ErrMaxInstances = errors.New("max number of instances ongoing, please wait")

type SensitiveError struct {
	Err          error
	PresentedErr string
}

func (e *SensitiveError) Error() string {
	return e.Err.Error()
}

// WriteJSON writes data to JSON file
func WriteJSON(filePth string, data any) error {
	file, err := os.OpenFile(filepath.Clean(filePth), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(data)
}

// HexToAddress converts a string HEX representation of Ethereum address to Address structure
func HexToAddress(s string) (common.Address, error) {
	var a common.Address
	if has0xPrefix(s) {
		s = s[2:]
	}
	decodedBytes, err := hex.DecodeString(s)
	if err != nil {
		return common.Address{}, err
	}
	if len(decodedBytes) != 20 {
		return common.Address{}, fmt.Errorf("not valid ETH address with len %d", len(decodedBytes))
	}
	a.SetBytes(decodedBytes)
	return a, nil
}

// has0xPrefix check if 0x is at the beginning of a HEX string
func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
}

// SplitBytes split bytes slice to n parts
func SplitBytes(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf)
	}
	return chunks
}

// GetThreshold computes threshold from amount of operators following 3f+1 tolerance
func GetThreshold[S ~[]E, E any](ids S) int {
	return len(ids) - ((len(ids) - 1) / 3)
}

func WriteErrorResponse(logger *zap.Logger, writer http.ResponseWriter, err error, statusCode int) {
	logger.Error("request error: " + err.Error())
	writer.WriteHeader(statusCode)
	presentedErr := err

	// Don't expose internal errors to the client.
	var sensitiveError *SensitiveError
	if errors.As(err, &sensitiveError) {
		presentedErr = errors.New(sensitiveError.PresentedErr)
	}

	_, writeErr := writer.Write(wire.MakeErr(presentedErr))
	if writeErr != nil {
		logger.Error("error writing error response: " + writeErr.Error())
	}
}

// GetNonce returns a suitable nonce to feed in the DKG config.
func GetNonce(input []byte) []byte {
	ret := sha256.Sum256(input)
	return ret[:]
}

// JoinSets creates a set of two groups of operators. For example: [1,2,3,4] and [1,2,5,6,7] will return [1,2,3,4,5,6,7]
func JoinSets(oldOperators, newOperators []*spec.Operator) ([]*spec.Operator, error) {
	if err := ValidateOpsLen(len(oldOperators)); err != nil {
		return nil, fmt.Errorf("wrong old ops len: %w", err)
	}
	if err := ValidateOpsLen(len(newOperators)); err != nil {
		return nil, fmt.Errorf("wrong new ops len: %w", err)
	}
	tmp := make(map[uint64]*spec.Operator)
	var set []*spec.Operator
	for _, op := range oldOperators {
		if _, ok := tmp[op.ID]; !ok {
			tmp[op.ID] = op
		}
	}
	for _, op := range newOperators {
		if _, ok := tmp[op.ID]; !ok {
			tmp[op.ID] = op
		}
	}
	for _, op := range tmp {
		set = append(set, op)
	}
	// sort array
	sort.SliceStable(set, func(i, j int) bool {
		return set[i].ID < set[j].ID
	})
	return set, nil
}

// GetCommonOldOperators returns an old set of operators disjoint from new set
// For example: old set [1,2,3,4,5]; new set [3,4,5,6,7]; returns [3,4,5]
func GetCommonOldOperators(oldOperators, newOperators []*spec.Operator) ([]*spec.Operator, error) {
	if err := ValidateOpsLen(len(oldOperators)); err != nil {
		return nil, fmt.Errorf("wrong old ops len: %w", err)
	}
	if err := ValidateOpsLen(len(newOperators)); err != nil {
		return nil, fmt.Errorf("wrong new ops len: %w", err)
	}
	tmp := make(map[uint64]*spec.Operator)
	var set []*spec.Operator
	for _, op := range newOperators {
		if _, ok := tmp[op.ID]; !ok {
			tmp[op.ID] = op
		}
	}
	for _, op := range oldOperators {
		if _, ok := tmp[op.ID]; ok {
			set = append(set, op)
		}
	}
	// sort array
	sort.SliceStable(set, func(i, j int) bool {
		return set[i].ID < set[j].ID
	})
	return set, nil
}

// GetDisjointNewOperators returns a new set of operators disjoint from old set
// For example: old set [1,2,3,4,5]; new set [3,4,5,6,7]; returns [6,7]
func GetDisjointNewOperators(oldOperators, newOperators []*spec.Operator) ([]*spec.Operator, error) {
	if err := ValidateOpsLen(len(oldOperators)); err != nil {
		return nil, fmt.Errorf("wrong old ops len: %w", err)
	}
	if err := ValidateOpsLen(len(newOperators)); err != nil {
		return nil, fmt.Errorf("wrong new ops len: %w", err)
	}
	tmp := make(map[uint64]*spec.Operator)
	var set []*spec.Operator
	for _, op := range newOperators {
		if _, ok := tmp[op.ID]; !ok {
			tmp[op.ID] = op
		}
	}
	for _, op := range oldOperators {
		delete(tmp, op.ID)
	}
	for _, op := range tmp {
		set = append(set, op)
	}
	// sort array
	sort.SliceStable(set, func(i, j int) bool {
		return set[i].ID < set[j].ID
	})
	return set, nil
}

func GetOpIDs(ops []*spec.Operator) []uint64 {
	ids := make([]uint64, 0)
	for _, op := range ops {
		ids = append(ids, op.ID)
	}
	return ids
}

func ValidateOpsLen(len int) error {
	switch len {
	case 4, 7, 10, 13:
		return nil
	default:
		return fmt.Errorf("amount of operators should be 4,7,10,13: got %d", len)
	}
}
