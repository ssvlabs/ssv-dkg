package operator

import (
	"crypto/rsa"
	"fmt"

	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/dkg"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// Instance interface to process messages at DKG instances incoming from initiator
type Instance interface {
	ProcessMessages(msg *wire.MultipleSignedTransports) ([]byte, error)
	VerifyInitiatorMessage(msg, sig []byte) error
}

// instWrapper wraps LocalOwner instance with RSA public key
type instWrapper struct {
	*dkg.LocalOwner                   // main DKG ceremony instance
	InitiatorPublicKey *rsa.PublicKey // initiator's RSA public key to verify its identity. Makes sure that in the DKG process messages received only from one initiator who started it.
	respChan           chan []byte    // channel to receive response
}

// VerifyInitiatorMessage verifies initiator message signature
func (iw *instWrapper) VerifyInitiatorMessage(msg, sig []byte) error {
	pubKey, err := spec_crypto.EncodeRSAPublicKey(iw.InitiatorPublicKey)
	if err != nil {
		return err
	}
	if err := spec_crypto.VerifyRSA(iw.InitiatorPublicKey, msg, sig); err != nil {
		return fmt.Errorf("failed to verify a message from initiator: %x", pubKey)
	}
	iw.Logger.Info("Successfully verified initiator message signature", zap.Uint64("from", iw.ID))
	return nil
}

func (iw *instWrapper) ProcessMessages(msg *wire.MultipleSignedTransports) ([]byte, error) {
	var multipleMsgsBytes []byte
	for _, transportMsg := range msg.Messages {
		msgBytes, err := transportMsg.MarshalSSZ()
		if err != nil {
			return nil, fmt.Errorf("process message: failed to ssz marshal message: %w", err)
		}
		multipleMsgsBytes = append(multipleMsgsBytes, msgBytes...)
	}
	// Verify initiator signature
	err := iw.VerifyInitiatorMessage(multipleMsgsBytes, msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("process message: failed to verify initiator signature: %w", err)
	}

	// check that we received enough messages from other operator participants
	ops, err := iw.CheckIncomingOperators(msg.Messages)
	if err != nil {
		return nil, err
	}
	var incOperators []*spec.Operator
	for _, op := range ops {
		incOperators = append(incOperators, op)
	}
	incOperators = spec.OrderOperators(incOperators)
	if !spec.UniqueAndOrderedOperators(incOperators) {
		return nil, fmt.Errorf("operators at incoming messages are not unique")
	}
	for _, ts := range msg.Messages {
		err = iw.Process(ts, incOperators)
		if err != nil {
			return nil, fmt.Errorf("process message: failed to process dkg message: %w", err)
		}
	}
	return <-iw.respChan, nil
}
