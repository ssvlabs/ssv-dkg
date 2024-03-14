package crypto

import "crypto/rsa"

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
	return SignRSA(s.sk, msg)
}
