package board

import (
	"github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"

	wire2 "github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// Board is the interface between the dkg protocol and the external world. It
// consists in pushing packets out to other nodes and receiving in packets from
// the other nodes. A common board would use the network as the underlying
// communication mechanism but one can also use a smart contract based
// approach.
type Board struct {
	logger         *zap.Logger
	broadcastF     func(msg *wire2.KyberMessage) error
	DealC          chan dkg.DealBundle
	ResponseC      chan dkg.ResponseBundle
	JustificationC chan dkg.JustificationBundle
}

// NewBoard creates a new instance of Board structure
func NewBoard(
	logger *zap.Logger,
	broadcastF func(msg *wire2.KyberMessage) error,
) *Board {
	return &Board{
		broadcastF:     broadcastF,
		logger:         logger,
		DealC:          make(chan dkg.DealBundle),
		ResponseC:      make(chan dkg.ResponseBundle),
		JustificationC: make(chan dkg.JustificationBundle),
	}
}

// PushDeals implements a kyber DKG Board interface to broadcast deal bundle
func (b *Board) PushDeals(bundle *dkg.DealBundle) {
	b.logger.Info("Pushing deal bundle: ", zap.Int("num of deals", len(bundle.Deals)))

	byts, err := wire2.EncodeDealBundle(bundle)
	if err != nil {
		b.logger.Error("error encoding deal bundle", zap.Error(err))
		return
	}
	msg := &wire2.KyberMessage{
		Type: wire2.KyberDealBundleMessageType,
		Data: byts,
	}

	if err := b.broadcastF(msg); err != nil {
		b.logger.Error("error broadcasting deal bundle", zap.Error(err))
		return
	}
}

// IncomingDeal implements a kyber DKG Board interface function
func (b *Board) IncomingDeal() <-chan dkg.DealBundle {
	return b.DealC
}

// PushResponses implements a kyber DKG Board interface to broadcast responses

// A response bundle is returned if there is any invalid or
// missing deals.
func (b *Board) PushResponses(bundle *dkg.ResponseBundle) {
	b.logger.Info("Pushing response bundle: ", zap.Int("num of responses", len(bundle.Responses)))
	byts, err := wire2.EncodeResponseBundle(bundle)
	if err != nil {
		b.logger.Error("error encoding response bundle", zap.Error(err))
		return
	}
	msg := &wire2.KyberMessage{
		Type: wire2.KyberResponseBundleMessageType,
		Data: byts,
	}

	if err := b.broadcastF(msg); err != nil {
		b.logger.Error("error broadcasting response bundle", zap.Error(err))
		return
	}
}

// IncomingResponse implements a kyber DKG Board interface function
func (b *Board) IncomingResponse() <-chan dkg.ResponseBundle {
	return b.ResponseC
}

// PushJustifications implements a kyber DKG interface to broadcast justifications
func (b *Board) PushJustifications(bundle *dkg.JustificationBundle) {
	b.logger.Info("Pushing justifications bundle: ", zap.Int("num of justifications", len(bundle.Justifications)))
	byts, err := wire2.EncodeJustificationBundle(bundle)
	if err != nil {
		b.logger.Error("error encoding justifications bundle", zap.Error(err))
		return
	}
	msg := &wire2.KyberMessage{
		Type: wire2.KyberJustificationBundleMessageType,
		Data: byts,
	}

	if err := b.broadcastF(msg); err != nil {
		b.logger.Error("error broadcasting justifications bundle", zap.Error(err))
		return
	}
}

// IncomingJustification implements a kyber DKG Board interface function
func (b *Board) IncomingJustification() <-chan dkg.JustificationBundle {
	return b.JustificationC
}
