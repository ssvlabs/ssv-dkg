package board

import (
	"errors"

	"github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"

	wire2 "github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

var ErrIncomingQueueFull = errors.New("incoming board queue full")

type config struct {
	incomingBufferSize int
}

type Option func(*config)

// WithIncomingBufferSize sets the channel buffer size for incoming protocol messages
// (deals/responses/justifications). Panics if size < 1.
func WithIncomingBufferSize(size int) Option {
	return func(c *config) {
		if size < 1 {
			panic("incoming buffer size must be >= 1")
		}
		c.incomingBufferSize = size
	}
}

// Board is the interface between the dkg protocol and the external world. It
// consists in pushing packets out to other nodes and receiving in packets from
// the other nodes. A common board would use the network as the underlying
// communication mechanism but one can also use a smart contract based
// approach.
type Board struct {
	logger         *zap.Logger
	broadcastF     func(msg *wire2.KyberMessage) error
	dealC          chan dkg.DealBundle
	responseC      chan dkg.ResponseBundle
	justificationC chan dkg.JustificationBundle
}

// NewBoard creates a new instance of Board structure
func NewBoard(
	logger *zap.Logger,
	broadcastF func(msg *wire2.KyberMessage) error,
	opts ...Option,
) *Board {
	cfg := config{
		incomingBufferSize: 1,
	}
	for _, opt := range opts {
		opt(&cfg)
	}
	return &Board{
		broadcastF:     broadcastF,
		logger:         logger,
		dealC:          make(chan dkg.DealBundle, cfg.incomingBufferSize),
		responseC:      make(chan dkg.ResponseBundle, cfg.incomingBufferSize),
		justificationC: make(chan dkg.JustificationBundle, cfg.incomingBufferSize),
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
	return b.dealC
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
	return b.responseC
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
	return b.justificationC
}

func enqueueNonBlocking[T any](ch chan<- T, v T) error {
	select {
	case ch <- v:
		return nil
	default:
		return ErrIncomingQueueFull
	}
}

// EnqueueDeal delivers a deal bundle into the DKG protocol.
func (b *Board) EnqueueDeal(bundle dkg.DealBundle) error {
	return enqueueNonBlocking(b.dealC, bundle)
}

// EnqueueResponse delivers a response bundle into the DKG protocol.
func (b *Board) EnqueueResponse(bundle dkg.ResponseBundle) error {
	return enqueueNonBlocking(b.responseC, bundle)
}

// EnqueueJustification delivers a justification bundle into the DKG protocol.
func (b *Board) EnqueueJustification(bundle dkg.JustificationBundle) error {
	return enqueueNonBlocking(b.justificationC, bundle)
}
