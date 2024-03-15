package operator

import (
	"crypto/rsa"
	"fmt"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"
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
	pubKey, err := crypto.EncodeRSAPublicKey(iw.InitiatorPublicKey)
	if err != nil {
		return err
	}
	if err := crypto.VerifyRSA(iw.InitiatorPublicKey, msg, sig); err != nil {
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
			return nil, fmt.Errorf("process message: failed to marshal message: %s", err.Error())
		}
		multipleMsgsBytes = append(multipleMsgsBytes, msgBytes...)
	}
	// Verify initiator signature
	err := iw.VerifyInitiatorMessage(multipleMsgsBytes, msg.Signature)
	if err != nil {
		return nil, fmt.Errorf("process message: failed to verify initiator signature: %s", err.Error())
	}
	for _, ts := range msg.Messages {
		err = iw.Process(ts)
		if err != nil {
			return nil, fmt.Errorf("process message: failed to process dkg message: %s", err.Error())
		}
	}
	return <-iw.respChan, nil
}
