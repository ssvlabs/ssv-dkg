package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"

	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/ethereum/go-ethereum/common"
)

// WriteJSON writes data to JSON file
func WriteJSON(filepath string, data any) error {
	file, err := os.Create(filepath)
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
		chunks = append(chunks, buf[:])
	}
	return chunks
}

// GetThreshold computes threshold from amount of operators following 3f+1 tolerance
func GetThreshold(ids []uint64) (int, error) {
	if len(ids) < 4 {
		return 0, fmt.Errorf("minimum supported amount of operators is 4")
	}
	// limit amount of operators
	if len(ids) > 13 {
		return 0, fmt.Errorf("maximum supported amount of operators is 13")
	}
	threshold := len(ids) - ((len(ids) - 1) / 3)
	return threshold, nil
}

// JoinSets creates a set of two groups of operators. For example: [1,2,3,4] and [1,2,5,6,7] will return [1,2,3,4,5,6,7]
func JoinSets(oldOperators []*wire.Operator, newOperators []*wire.Operator) []*wire.Operator {
	tmp := make(map[uint64]*wire.Operator)
	var set []*wire.Operator
	for _, op := range oldOperators {
		if tmp[op.ID] == nil {
			tmp[op.ID] = op
		}
	}
	for _, op := range newOperators {
		if tmp[op.ID] == nil {
			tmp[op.ID] = op
		}
	}
	for _, op := range tmp {
		set = append(set, op)
	}
	return set
}

// GetNetworkByFork translates the network fork bytes into name
//
//	TODO: once eth2_key_manager implements this we can get rid of it and support all networks ekm supports automatically
func GetNetworkByFork(fork [4]byte) eth2_key_manager_core.Network {
	switch fork {
	case [4]byte{0x00, 0x00, 0x10, 0x20}:
		return eth2_key_manager_core.PraterNetwork
	case [4]byte{0x01, 0x01, 0x70, 0x00}:
		return eth2_key_manager_core.HoleskyNetwork
	case [4]byte{0, 0, 0, 0}:
		return eth2_key_manager_core.MainNetwork
	default:
		return eth2_key_manager_core.MainNetwork
	}
}

// GetDisjointOldOperators returns an old set of operators disjoint from new set
// For example: old set [1,2,3,4,5]; new set [3,4,5,6,7]; returns [3,4,5]
func GetDisjointOldOperators(oldOperators []*wire.Operator, newOperators []*wire.Operator) []*wire.Operator {
	tmp := make(map[uint64]*wire.Operator)
	var set []*wire.Operator
	for _, op := range newOperators {
		if tmp[op.ID] == nil {
			tmp[op.ID] = op
		}
	}
	for _, op := range oldOperators {
		if tmp[op.ID] != nil {
			set = append(set, op)
		}
	}
	return set
}

// GetDisjointNewOperators returns a new set of operators disjoint from old set
// For example: old set [1,2,3,4,5]; new set [3,4,5,6,7]; returns [6,7]
func GetDisjointNewOperators(oldOperators []*wire.Operator, newOperators []*wire.Operator) []*wire.Operator {
	tmp := make(map[uint64]*wire.Operator)
	var set []*wire.Operator
	for _, op := range newOperators {
		if tmp[op.ID] == nil {
			tmp[op.ID] = op
		}
	}
	for _, op := range oldOperators {
		if tmp[op.ID] != nil {
			delete(tmp, op.ID)
		}
	}
	for _, op := range tmp {
		set = append(set, op)
	}
	return set
}

// storeSecretShareToFile writes encrypted secret share to JSON file at provided outputPath
func StoreSecretShareToFile(outputPath string, index int, encryptedSecretShare []byte, validatorPubKey *bls.PublicKey) error {
	type shareStorage struct {
		Index  int    `json:"index"`
		Secret string `json:"secret"`
	}
	data := shareStorage{
		Index:  index,
		Secret: hex.EncodeToString(encryptedSecretShare),
	}
	err := WriteJSON(outputPath+"secret_share_"+fmt.Sprintf("%d", data.Index)+"_"+validatorPubKey.SerializeToHexStr(), &data)
	if err != nil {
		return err
	}
	return nil
}
