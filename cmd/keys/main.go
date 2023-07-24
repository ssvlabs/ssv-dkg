package main

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"fmt"
	"log"
	"os"
)

func main() {
	p := "../../examples/server"

	for i := 1; i <= 4; i++ {

		finalpath := fmt.Sprintf("%v%v/key", p, i)
		fmt.Println(finalpath)

		k, err := loadPrivateKey(finalpath)
		if err != nil {
			log.Fatalf("fatal %v", err)
		}

		pkBytes, err := x509.MarshalPKIXPublicKey(&k.PublicKey)
		if err != nil {
			log.Fatalf("err %v", err)
		}
		pemByte := pem.EncodeToMemory(
			&pem.Block{
				Type:  "RSA PUBLIC KEY",
				Bytes: pkBytes,
			},
		)

		strpubkey := base64.StdEncoding.EncodeToString(pemByte)
		fmt.Println(strpubkey)
		operatorKeyByte, err := base64.StdEncoding.DecodeString(strpubkey)
		if err != nil {
			log.Fatalf("wrF %v", err)
		}
		pemblock, _ := pem.Decode(operatorKeyByte)
		pbkey, err := x509.ParsePKCS1PublicKey(pemblock.Bytes)
		if err != nil {
			log.Fatalf("wrf2 %v", err)
		}
		fmt.Println(pbkey)
	}

}

func loadPrivateKey(path string) (*rsa.PrivateKey, error) {
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

//	privateKey, err := x509.ParsePKCS1PrivateKey(operatorKeyByte)
//	if err != nil {
//		return nil, fmt.Errorf("failed to parse PKCS1 private key: %w", err)
//	}
//
//	return privateKey, nil
//}
