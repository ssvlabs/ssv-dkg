package operator

import (
	"context"
	"crypto/rsa"
	"fmt"
	"sync"

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
	// Close cancels in-flight goroutines bound to this instance. Idempotent.
	Close()
}

// instWrapper wraps LocalOwner instance with RSA public key
type instWrapper struct {
	*dkg.LocalOwner                   // main DKG ceremony instance
	InitiatorPublicKey *rsa.PublicKey // initiator's RSA public key to verify its identity. Makes sure that in the DKG process messages received only from one initiator who started it.
	respChan           chan []byte    // channel to receive response
	cancel             context.CancelFunc
	// procMu serializes ProcessMessages per instance. LocalOwner mutates
	// exchanges/deals maps and closes startedDKG without its own locking;
	// concurrent /dkg retries for the same InstanceID would race those.
	procMu sync.Mutex
}

func (iw *instWrapper) Close() {
	if iw.cancel != nil {
		iw.cancel()
	}
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
	iw.procMu.Lock()
	defer iw.procMu.Unlock()

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
	// Phase ctx is Background-derived so the per-call budget is not shrunk by
	// instance age. iw.Ctx() is observed separately so Close()/reaper
	// cancellation still short-circuits the wait.
	phaseCtx, phaseCancel := context.WithTimeout(context.Background(), MaxInstancePhaseTimeout)
	defer phaseCancel()
	select {
	case resp, ok := <-iw.respChan:
		if !ok {
			return nil, fmt.Errorf("process message: response channel closed")
		}
		return resp, nil
	case <-phaseCtx.Done():
		// Broadcast checks instanceCtx before writing but the check-then-send
		// is a TOCTOU — a response can land in respChan concurrently with
		// phase deadline. The non-blocking re-check catches that window.
		select {
		case resp, ok := <-iw.respChan:
			if !ok {
				return nil, fmt.Errorf("process message: response channel closed")
			}
			return resp, nil
		default:
			return nil, fmt.Errorf("process message: timed out waiting for response: %w", phaseCtx.Err())
		}
	case <-iw.Ctx().Done():
		// Instance lifecycle ended (Close, reaper, or MaxInstanceTime).
		select {
		case resp, ok := <-iw.respChan:
			if !ok {
				return nil, fmt.Errorf("process message: response channel closed")
			}
			return resp, nil
		default:
			return nil, fmt.Errorf("process message: instance lifecycle ended: %w", iw.Ctx().Err())
		}
	}
}
