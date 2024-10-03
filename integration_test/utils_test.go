package integration_test

import (
	"crypto/ecdsa"
	"encoding/hex"

	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func SignReshare(msg []*wire.ReshareMessage, sk *ecdsa.PrivateKey) (string, error) {
	hash, err := utils.GetMessageHash(msg)
	if err != nil {
		return "", err
	}
	// Sign message root
	ownerSigBytes, err := eth_crypto.Sign(hash[:], sk)
	if err != nil {
		return "", err
	}
	sig := hex.EncodeToString(ownerSigBytes)
	return sig, nil
}
