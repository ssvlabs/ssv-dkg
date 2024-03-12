package initiator

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// VerifyMessageSignatures verifies incoming to initiator messages from operators.
// Incoming message from operator should have same DKG ceremony ID and a valid signature
func VerifyMessageSignatures(id [24]byte, messages [][]byte, verify VerifyMessageSignature) error {
	var errs error
	for i := 0; i < len(messages); i++ {
		msg := messages[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := ParseAsError(msg)
			if parseErr == nil {
				errs = errors.Join(errs, fmt.Errorf("%v", errmsg))
				continue
			}
			return err
		}
		signedBytes, err := tsp.Message.MarshalSSZ()
		if err != nil {
			return err
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return fmt.Errorf("incoming message has wrong ID, aborting... operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		// Verification operator signatures
		if err := verify(tsp.Signer, signedBytes, tsp.Signature); err != nil {
			return err
		}
	}
	return errs
}

// MakeMultipleSignedTransports creates a one combined message from operators with initiator signature
func MakeMultipleSignedTransports(privateKey *rsa.PrivateKey, id [24]byte, messages [][]byte) (*wire.MultipleSignedTransports, error) {
	// We are collecting responses at SendToAll which gives us int(msg)==int(oprators)
	final := &wire.MultipleSignedTransports{
		Identifier: id,
		Messages:   make([]*wire.SignedTransport, len(messages)),
	}
	var allMsgsBytes []byte
	for i := 0; i < len(messages); i++ {
		msg := messages[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := ParseAsError(msg)
			if parseErr == nil {
				return nil, fmt.Errorf("msg %d returned: %v", i, errmsg)
			}
			return nil, err
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return nil, fmt.Errorf("incoming message has wrong ID, aborting... operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		final.Messages[i] = tsp
		allMsgsBytes = append(allMsgsBytes, msg...)
	}
	// sign message by initiator
	sig, err := crypto.SignRSA(privateKey, allMsgsBytes)
	if err != nil {
		return nil, err
	}
	final.Signature = sig
	return final, nil
}
