package initiator

import (
	"bytes"
	"crypto/rsa"
	"errors"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// standardMessageVerification creates function to verify each participating operator RSA signature for incoming to initiator messages
func standardMessageVerification(ops Operators) func(id uint64, msg []byte, sig []byte) error {
	inst_ops := make(map[uint64]*rsa.PublicKey)
	for _, op := range ops {
		inst_ops[op.ID] = op.PubKey
	}
	return func(id uint64, msg []byte, sig []byte) error {
		pk, ok := inst_ops[id]
		if !ok {
			return fmt.Errorf("cant find operator, was it provided at operators information file %d", id)
		}
		return crypto.VerifyRSA(pk, msg, sig)
	}
}

// verifyMessageSignatures verifies incoming to initiator messages from operators.
// Incoming message from operator should have same DKG ceremony ID and a valid signature
func verifyMessageSignatures(id [24]byte, messages [][]byte, verify VerifyMessageSignatureFunc) error {
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

// makeMultipleSignedTransports creates a one combined message from operators with initiator signature
func makeMultipleSignedTransports(privateKey *rsa.PrivateKey, id [24]byte, messages [][]byte) (*wire.MultipleSignedTransports, error) {
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
