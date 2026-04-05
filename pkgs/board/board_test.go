package board

import (
	"testing"

	kyber_dkg "github.com/drand/kyber/share/dkg"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestBoard_EnqueueDeal_NonBlockingWhenFull(t *testing.T) {
	t.Parallel()

	b := NewBoard(
		zap.NewNop(),
		func(*wire.KyberMessage) error { return nil },
		WithIncomingBufferSize(1),
	)

	require.NoError(t, b.EnqueueDeal(kyber_dkg.DealBundle{}))
	require.ErrorIs(t, b.EnqueueDeal(kyber_dkg.DealBundle{}), ErrIncomingQueueFull)

	select {
	case <-b.IncomingDeal():
	default:
		t.Fatalf("expected to be able to drain deal queue")
	}

	require.NoError(t, b.EnqueueDeal(kyber_dkg.DealBundle{}))
}

func TestBoard_EnqueueResponse_NonBlockingWhenFull(t *testing.T) {
	t.Parallel()

	b := NewBoard(
		zap.NewNop(),
		func(*wire.KyberMessage) error { return nil },
		WithIncomingBufferSize(1),
	)

	require.NoError(t, b.EnqueueResponse(kyber_dkg.ResponseBundle{}))
	require.ErrorIs(t, b.EnqueueResponse(kyber_dkg.ResponseBundle{}), ErrIncomingQueueFull)
}

func TestBoard_EnqueueJustification_NonBlockingWhenFull(t *testing.T) {
	t.Parallel()

	b := NewBoard(
		zap.NewNop(),
		func(*wire.KyberMessage) error { return nil },
		WithIncomingBufferSize(1),
	)

	require.NoError(t, b.EnqueueJustification(kyber_dkg.JustificationBundle{}))
	require.ErrorIs(t, b.EnqueueJustification(kyber_dkg.JustificationBundle{}), ErrIncomingQueueFull)
}
