package utils

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
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
