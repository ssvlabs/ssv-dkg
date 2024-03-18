package spec

import (
	"crypto/rsa"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
)

type Signer interface {
	Sign(msg []byte) ([]byte, error)
}

type rsaSigner struct {
	sk *rsa.PrivateKey
}

func RSASigner(sk *rsa.PrivateKey) Signer {
	return &rsaSigner{
		sk: sk,
	}
}

func (s *rsaSigner) Sign(msg []byte) ([]byte, error) {
	return crypto.SignRSA(s.sk, msg)
}
