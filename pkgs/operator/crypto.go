package operator

import (
	"crypto/rand"
	"crypto/rsa"

	"github.com/bloxapp/ssv/utils/rsaencryption"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
)

// Sign creates a RSA signature for the message at operator before sending it to initiator
func (s *Switch) Sign(msg []byte) ([]byte, error) {
	return spec_crypto.SignRSA(s.PrivateKey, msg)
}

// Encrypt with RSA public key private DKG share key
func (s *Switch) Encrypt(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, msg)
}

// Decrypt with RSA private key private DKG share key
func (s *Switch) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsaencryption.DecodeKey(s.PrivateKey, ciphertext)
}
