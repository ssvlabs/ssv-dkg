package crypto

import (
	"errors"
	"fmt"

	"github.com/drand/kyber/share"
	drand_dkg "github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
)

var (
	ErrInvalidSignature = errors.New("invalid signature")
)

const (
	// b64 encrypted key length is 256
	EncryptedKeyLength = 256
	// Signature len
	SignatureLength = 256
)

func init() {
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)
}

// ResultToShareSecretKey converts a private share at kyber DKG result to github.com/herumi/bls-eth-go-binary/bls private key
func ResultToShareSecretKey(result *drand_dkg.DistKeyShare) (*bls.SecretKey, error) {
	privShare := result.PriShare()
	bytsSk, err := privShare.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

// ResultsToValidatorPK converts a public polynomial at kyber DKG result to github.com/herumi/bls-eth-go-binary/bls public key
func ResultToValidatorPK(result *drand_dkg.DistKeyShare, suite drand_dkg.Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), result.Commitments())
	bytsPK, err := exp.Commit().MarshalBinary()
	if err != nil {
		return nil, fmt.Errorf("could not marshal share %w", err)
	}
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(bytsPK); err != nil {
		return nil, err
	}
	return pk, nil
}

// VerifyOwnerNonceSignature check that owner + nonce correctly signed
func VerifyOwnerNonceSignature(sig []byte, owner common.Address, pubKey []byte, nonce uint16) error {
	data := fmt.Sprintf("%s:%d", owner.String(), nonce)
	hash := eth_crypto.Keccak256([]byte(data))

	sign := &bls.Sign{}
	if err := sign.Deserialize(sig); err != nil {
		return fmt.Errorf("failed to deserialize signature: %w", err)
	}

	pk := &bls.PublicKey{}
	if err := pk.Deserialize(pubKey); err != nil {
		return fmt.Errorf("failed to deserialize public key: %w", err)
	}

	if res := sign.VerifyByte(pk, hash); !res {
		return ErrInvalidSignature
	}

	return nil
}
