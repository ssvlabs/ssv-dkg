package spec

import (
	"crypto/rsa"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
)

// SignCeremonyProof returns a signed ceremomy proof
func SignCeremonyProof(sk *rsa.PrivateKey, proof *Proof) (*SignedProof, error) {
	hash, err := proof.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	sig, err := crypto.SignRSA(sk, hash[:])
	if err != nil {
		return nil, err
	}

	return &SignedProof{
		Proof:     proof,
		Signature: sig,
	}, nil
}

// VerifyCeremonyProof returns error if ceremony signed proof is invalid
func VerifyCeremonyProof(pk *rsa.PublicKey, proof SignedProof) error {
	hash, err := proof.Proof.HashTreeRoot()
	if err != nil {
		return err
	}

	return crypto.VerifyRSA(pk, hash[:], proof.Signature)
}
