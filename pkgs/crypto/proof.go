package crypto

import (
	"bytes"
	"crypto/rsa"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// SignCeremonyProof returns a signed ceremomy proof
func SignCeremonyProof(signer Signer, proof *wire.Proof) (*wire.SignedProof, error) {
	hash, err := proof.HashTreeRoot()
	if err != nil {
		return nil, err
	}

	sig, err := signer.Sign(hash[:])
	if err != nil {
		return nil, err
	}

	return &wire.SignedProof{
		Proof:     proof,
		Signature: sig,
	}, nil
}

func ValidateCeremonyProof(
	ownerAddress [20]byte,
	operator *wire.Operator,
	signedProof wire.SignedProof,
) error {
	if !bytes.Equal(ownerAddress[:], signedProof.Proof.Owner[:]) {
		return fmt.Errorf("invalid owner address")
	}
	pk, err := ParseRSAPublicKey(operator.PubKey)
	if err != nil {
		return err
	}
	if err := VerifyCeremonyProof(pk, signedProof); err != nil {
		return err
	}
	return nil
}

// VerifyCeremonyProof returns error if ceremony signed proof is invalid
func VerifyCeremonyProof(pk *rsa.PublicKey, proof wire.SignedProof) error {
	hash, err := proof.Proof.HashTreeRoot()
	if err != nil {
		return err
	}
	return VerifyRSA(pk, hash[:], proof.Signature)
}
