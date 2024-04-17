package crypto

import (
	"crypto/rsa"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/dkg-spec/crypto"
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

func SignCeremonyProof(signer Signer, proof *spec.Proof) (*spec.SignedProof, error) {
	hash, err := proof.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	sig, err := signer.Sign(hash[:])
	if err != nil {
		return nil, err
	}

	return &spec.SignedProof{
		Proof:     proof,
		Signature: sig,
	}, nil
}
