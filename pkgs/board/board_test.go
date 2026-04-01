package board

import (
	"testing"

	kyber_dkg "github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestBoard_EnqueueDeal_NonBlockingWhenFull(t *testing.T) {
	t.Parallel()

	b := NewBoard(
		zap.NewNop(),
		func(*wire.KyberMessage) error { return nil },
		WithIncomingBufferSize(1),
		WithIncomingSendTimeout(0),
	)

	if err := b.EnqueueDeal(kyber_dkg.DealBundle{}); err != nil {
		t.Fatalf("expected first enqueue to succeed, got %v", err)
	}
	if err := b.EnqueueDeal(kyber_dkg.DealBundle{}); err != ErrIncomingQueueFull {
		t.Fatalf("expected ErrIncomingQueueFull, got %v", err)
	}

	select {
	case <-b.IncomingDeal():
	default:
		t.Fatalf("expected to be able to drain deal queue")
	}

	if err := b.EnqueueDeal(kyber_dkg.DealBundle{}); err != nil {
		t.Fatalf("expected enqueue after drain to succeed, got %v", err)
	}
}

func TestBoard_EnqueueResponse_NonBlockingWhenFull(t *testing.T) {
	t.Parallel()

	b := NewBoard(
		zap.NewNop(),
		func(*wire.KyberMessage) error { return nil },
		WithIncomingBufferSize(1),
		WithIncomingSendTimeout(0),
	)

	if err := b.EnqueueResponse(kyber_dkg.ResponseBundle{}); err != nil {
		t.Fatalf("expected first enqueue to succeed, got %v", err)
	}
	if err := b.EnqueueResponse(kyber_dkg.ResponseBundle{}); err != ErrIncomingQueueFull {
		t.Fatalf("expected ErrIncomingQueueFull, got %v", err)
	}
}

func TestBoard_EnqueueJustification_NonBlockingWhenFull(t *testing.T) {
	t.Parallel()

	b := NewBoard(
		zap.NewNop(),
		func(*wire.KyberMessage) error { return nil },
		WithIncomingBufferSize(1),
		WithIncomingSendTimeout(0),
	)

	if err := b.EnqueueJustification(kyber_dkg.JustificationBundle{}); err != nil {
		t.Fatalf("expected first enqueue to succeed, got %v", err)
	}
	if err := b.EnqueueJustification(kyber_dkg.JustificationBundle{}); err != ErrIncomingQueueFull {
		t.Fatalf("expected ErrIncomingQueueFull, got %v", err)
	}
}

