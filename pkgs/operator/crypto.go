package operator

import (
	"bytes"
	"crypto/rand"
	"crypto/rsa"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

// Sign creates a RSA signature for the message at operator before sending it to initiator
func (s *Switch) Sign(msg []byte) ([]byte, error) {
	return crypto.SignRSA(s.PrivateKey, msg)
}

// Encrypt with RSA public key private DKG share key
func (s *Switch) Encrypt(msg []byte) ([]byte, error) {
	return rsa.EncryptPKCS1v15(rand.Reader, &s.PrivateKey.PublicKey, msg)
}

// Decrypt with RSA private key private DKG share key
func (s *Switch) Decrypt(ciphertext []byte) ([]byte, error) {
	return rsaencryption.DecodeKey(s.PrivateKey, ciphertext)
}

// CreateVerifyFunc verifies signatures for operators participating at DKG ceremony
func (s *Switch) CreateVerifyFunc(ops []*wire.Operator) (func(pub, msg []byte, sig []byte) error, error) {
	return func(pub, msg []byte, sig []byte) error {
		var ok bool
		for _, op := range ops {
			if bytes.Equal(op.PubKey, pub) {
				ok = true
				break
			}
		}
		if !ok {
			return fmt.Errorf("cant find operator participating at DKG %x", pub)
		}
		rsaPub, err := crypto.ParseRSAPublicKey(pub)
		if err != nil {
			return err
		}
		return crypto.VerifyRSA(rsaPub, msg, sig)
	}, nil
}

func VerifySig(incMsg *wire.SignedTransport, initiatorPubKey *rsa.PublicKey) error {
	marshalledWireMsg, err := incMsg.Message.MarshalSSZ()
	if err != nil {
		return err
	}
	err = crypto.VerifyRSA(initiatorPubKey, marshalledWireMsg, incMsg.Signature)
	if err != nil {
		return fmt.Errorf("signature isn't valid: %s", err.Error())
	}
	return nil
}
