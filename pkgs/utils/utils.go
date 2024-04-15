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

	"github.com/ethereum/go-ethereum/common"
	"go.uber.org/zap"

	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
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
func GetThreshold(ids []uint64) (int, error) {
	threshold := len(ids) - ((len(ids) - 1) / 3)
	return threshold, nil
}

// GetNetworkByFork translates the network fork bytes into name
//
//	TODO: once eth2_key_manager implements this we can get rid of it and support all networks ekm supports automatically
func GetNetworkByFork(fork [4]byte) (eth2_key_manager_core.Network, error) {
	switch fork {
	case [4]byte{0x00, 0x00, 0x10, 0x20}:
		return eth2_key_manager_core.PraterNetwork, nil
	case [4]byte{0x01, 0x01, 0x70, 0x00}:
		return eth2_key_manager_core.HoleskyNetwork, nil
	case [4]byte{0, 0, 0, 0}:
		return eth2_key_manager_core.MainNetwork, nil
	default:
		return eth2_key_manager_core.MainNetwork, errors.New("unknown network")
	}
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
