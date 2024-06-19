package initiator

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
)

// standardMessageVerification creates function to verify each participating operator RSA signature for incoming to initiator messages
func standardMessageVerification(ops wire.OperatorsCLI) func(pk *rsa.PublicKey, msg []byte, sig []byte) error {
	return func(pk *rsa.PublicKey, msg []byte, sig []byte) error {
		op := ops.ByPubKey(pk)

		if op == nil {
			encodedPk, _ := spec_crypto.EncodeRSAPublicKey(pk)
			return fmt.Errorf("cant find operator participating at DKG %s", string(encodedPk))
		}

		return spec_crypto.VerifyRSA(pk, msg, sig)
	}
}

// verifyMessageSignatures verifies incoming to initiator messages from operators.
// Incoming message from operator should have same DKG ceremony ID and a valid signature
func verifyMessageSignatures(id [24]byte, messages map[uint64][]byte, verify VerifyMessageSignatureFunc) error {
	var errs error
	for _, msg := range messages {
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := wire.ParseAsError(msg)
			if parseErr == nil {
				errs = errors.Join(errs, fmt.Errorf("%v", errmsg))
				continue
			}
			return err
		}
		signedBytes, err := tsp.Message.MarshalSSZ()
		if err != nil {
			return fmt.Errorf("failed to marshal message: %w", err)
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return fmt.Errorf("incoming message has wrong ID, aborting... operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		// Verification operator signatures
		pk, err := spec_crypto.ParseRSAPublicKey(tsp.Signer)
		if err != nil {
			return fmt.Errorf("failed to parse RSA key: %w", err)
		}
		if err := verify(pk, signedBytes, tsp.Signature); err != nil {
			return fmt.Errorf("failed to verify RSA signature: %w", err)
		}
	}
	return errs
}

// makeMultipleSignedTransports creates a one combined message from operators with initiator signature
func makeMultipleSignedTransports(privateKey *rsa.PrivateKey, id [24]byte, messages map[uint64][]byte) (*wire.MultipleSignedTransports, error) {
	// We are collecting responses at SendToAll which gives us int(msg)==int(oprators)
	final := &wire.MultipleSignedTransports{
		Identifier: id,
		Messages:   make([]*wire.SignedTransport, len(messages)),
	}
	var allMsgsBytes []byte
	count := 0
	for i, msg := range messages {
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := wire.ParseAsError(msg)
			if parseErr == nil {
				return nil, fmt.Errorf("operator %d returned: %v", i, errmsg)
			}
			return nil, err
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return nil, fmt.Errorf("incoming message has wrong ID, aborting... operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		final.Messages[count] = tsp
		allMsgsBytes = append(allMsgsBytes, msg...)
		count++
	}
	// sign message by initiator
	sig, err := spec_crypto.SignRSA(privateKey, allMsgsBytes)
	if err != nil {
		return nil, err
	}
	final.Signature = sig
	return final, nil
}
