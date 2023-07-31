package load

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"os"
)

func PrivateKey(path string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	operatorKeyByte, err := base64.StdEncoding.DecodeString(string(data))
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(operatorKeyByte)
	// TODO: resolve deprecation https://github.com/golang/go/issues/8860
	enc := x509.IsEncryptedPEMBlock(block) //nolint
	b := block.Bytes
	if enc {
		var err error
		// TODO: resolve deprecation https://github.com/golang/go/issues/8860
		b, err = x509.DecryptPEMBlock(block, nil) //nolint
		if err != nil {
			return nil, err
		}
	}
	parsedSk, err := x509.ParsePKCS1PrivateKey(b)
	if err != nil {
		return nil, err
	}
	return parsedSk, nil
}
