package spec

import (
	"bytes"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
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
	validatorPK []byte,
	operator *wire.Operator,
	signedProof wire.SignedProof,
) error {
	if !bytes.Equal(ownerAddress[:], signedProof.Proof.Owner[:]) {
		return fmt.Errorf("invalid owner address")
	}
	// verify validator pk
	if !bytes.Equal(validatorPK, signedProof.Proof.ValidatorPubKey) {
		return fmt.Errorf("invalid proof validator pubkey")
	}
	if err := VerifyCeremonyProof(operator.PubKey, signedProof); err != nil {
		return err
	}
	return nil
}

// VerifyCeremonyProof returns error if ceremony signed proof is invalid
func VerifyCeremonyProof(pkBytes []byte, proof wire.SignedProof) error {
	hash, err := proof.Proof.HashTreeRoot()
	if err != nil {
		return err
	}
	pk, err := crypto.ParseRSAPublicKey(pkBytes)
	if err != nil {
		return err
	}
	return crypto.VerifyRSA(pk, hash[:], proof.Signature)
}
