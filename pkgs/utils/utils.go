package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"os"

	"github.com/ethereum/go-ethereum/common"
)

func WriteJSON(filepath string, data any) error {
	file, err := os.Create(filepath)
	if err != nil {
		return err
	}
	defer file.Close()
	return json.NewEncoder(file).Encode(data)
}

func HexToAddress(s string) (common.Address, error) {
	var a common.Address
	if has0xPrefix(s) {
		s = s[2:]
	}
	// if len(s)%2 == 1 {
	// 	s = "0" + s
	// }
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

func has0xPrefix(str string) bool {
	return len(str) >= 2 && str[0] == '0' && (str[1] == 'x' || str[1] == 'X')
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
