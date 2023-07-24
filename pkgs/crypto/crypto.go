package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"github.com/drand/kyber"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/herumi/bls-eth-go-binary/bls"
)

func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	return pv, &pv.PublicKey, nil

}

func SignRSA(sk *rsa.PrivateKey, byts []byte) ([]byte, error) {
	r := sha256.Sum256(byts)
	return sk.Sign(rand.Reader, r[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// Encrypt with secret key (base64) the bytes, return the encrypted key string
func Encrypt(pk *rsa.PublicKey, plainText []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pk, plainText)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

func VerifyRSA(pk *rsa.PublicKey, msg, signature []byte) error {
	r := sha256.Sum256(msg)
	return rsa.VerifyPSS(pk, crypto.SHA256, r[:], signature, nil)
}

func ResultToShareSecretKey(result *dkg.Result) (*bls.SecretKey, error) {
	share := result.Key.PriShare()
	bytsSk, err := share.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

func ResultsToValidatorPK(commitments []kyber.Point, suite dkg.Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), commitments)
	bytsPK, err := exp.Eval(0).V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(bytsPK); err != nil {
		return nil, err
	}
	return pk, nil
}
