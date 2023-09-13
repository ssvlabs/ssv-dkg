package load

import (
	"bytes"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/csv"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"strconv"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/initiator"
)

func Operators(path string) (initiator.Operators, error) {
	opmap := make(map[uint64]initiator.Operator)

	opsfile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	opsv := csv.NewReader(bytes.NewReader(opsfile))

	ops, err := opsv.ReadAll()
	if err != nil {
		return nil, err
	}

	for _, opdata := range ops {
		id, err := strconv.ParseUint(opdata[0], 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		strkey := opdata[1]
		operatorKeyByte, err := base64.StdEncoding.DecodeString(strkey)
		if err != nil {
			return nil, err
		}
		pemBlock, _ := pem.Decode(operatorKeyByte)
		pbKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}
		ip := opdata[2]

		opmap[id] = initiator.Operator{
			Addr:   ip,
			ID:     id,
			PubKey: pbKey.(*rsa.PublicKey),
		}
	}
	return opmap, nil
}

func LoadOperatorsJson(operatorsMetaData []byte) (initiator.Operators, error) {
	opmap := make(map[uint64]initiator.Operator)
	var operators []initiator.OperatorDataJson
	err := json.Unmarshal(bytes.TrimSpace(operatorsMetaData), &operators)
	if err != nil {
		return nil, err
	}
	for _, opdata := range operators {
		operatorKeyByte, err := base64.StdEncoding.DecodeString(opdata.PubKey)
		if err != nil {
			return nil, err
		}
		pemBlock, _ := pem.Decode(operatorKeyByte)
		pbKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		opmap[opdata.ID] = initiator.Operator{
			Addr:   opdata.Addr,
			ID:     opdata.ID,
			PubKey: pbKey.(*rsa.PublicKey),
		}
	}
	return opmap, nil
}

func OperatorsPubkeys(path string) (map[uint64]*rsa.PublicKey, error) {
	opmap := make(map[uint64]*rsa.PublicKey)

	opsfile, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to open file: %w", err)
	}

	opsv := csv.NewReader(bytes.NewReader(opsfile))

	ops, err := opsv.ReadAll()
	if err != nil {
		return nil, err
	}

	for _, opdata := range ops {
		id, err := strconv.ParseUint(opdata[0], 10, strconv.IntSize)
		if err != nil {
			return nil, err
		}
		strkey := opdata[1]
		pbkey, err := crypto.ParseRSAPubkey([]byte(strkey))
		if err != nil {
			return nil, err
		}
		opmap[id] = pbkey
	}
	return opmap, nil
}
