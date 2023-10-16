package board

import (
	wire2 "github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"
)

type Board struct {
	logger *zap.Logger
	broadcastF     func(msg *wire2.KyberMessage) error
	DealC          chan dkg.DealBundle
	ResponseC      chan dkg.ResponseBundle
	JustificationC chan dkg.JustificationBundle
}

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

func (b *Board) PushDeals(bundle *dkg.DealBundle) {
	b.logger.Debug("Pushing deal bundle: ", zap.Int("num of deals", len(bundle.Deals)))

	byts, err := wire2.EncodeDealBundle(bundle)
	if err != nil {
		b.logger.Error(err.Error())
		return
	}

	msg := &wire2.KyberMessage{
		Type: wire2.KyberDealBundleMessageType,
		Data: byts,
	}

	if err := b.broadcastF(msg); err != nil {
		b.logger.Error(err.Error())
		return
	}
}

func (b *Board) IncomingDeal() <-chan dkg.DealBundle {
	return b.DealC
}

func (b *Board) PushResponses(bundle *dkg.ResponseBundle) {
	b.logger.Info("Pushing response bundle: ", zap.Int("num of responses", len(bundle.Responses)))

	byts, err := wire2.EncodeResponseBundle(bundle)
	if err != nil {
		b.logger.Error(err.Error())
		return
	}

	msg := &wire2.KyberMessage{
		Type: wire2.KyberResponseBundleMessageType,
		Data: byts,
	}

	if err := b.broadcastF(msg); err != nil {
		b.logger.Error(err.Error())
		return
	}
}

func (b *Board) IncomingResponse() <-chan dkg.ResponseBundle {
	return b.ResponseC
}

func (b *Board) PushJustifications(bundle *dkg.JustificationBundle) {
	b.logger.Info("Pushing justification bundle: ", zap.Int("num of responses", len(bundle.Justifications)))

	byts, err := wire2.EncodeJustificationBundle(bundle)
	if err != nil {
		b.logger.Error(err.Error())
		return
	}

	msg := &wire2.KyberMessage{
		Type: wire2.KyberJustificationBundleMessageType,
		Data: byts,
	}

	if err := b.broadcastF(msg); err != nil {
		b.logger.Error(err.Error())
		return
	}
}

func (b *Board) IncomingJustification() <-chan dkg.JustificationBundle {
	return b.JustificationC
}
