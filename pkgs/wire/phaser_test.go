package wire

import (
	"context"
	"testing"
	"time"

	"github.com/drand/kyber/share/dkg"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
)

func TestCancellablePhaser_EmitsAllPhasesWhenNotCancelled(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	p := newCancellablePhaser(t.Context(), 0)
	done := make(chan struct{})
	go func() {
		p.Start()
		close(done)
	}()

	phases := []dkg.Phase{dkg.DealPhase, dkg.ResponsePhase, dkg.JustifPhase, dkg.FinishPhase}
	for _, want := range phases {
		select {
		case got := <-p.NextPhase():
			require.Equal(t, want, got)
		case <-time.After(time.Second):
			t.Fatalf("timed out waiting for phase %s", want)
		}
	}

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not return after final phase")
	}
}

func TestCancellablePhaser_ExitsPromptlyOnCancel(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithCancel(t.Context())
	// 10s sleep would normally force a 30s total; we cancel immediately so the
	// phaser must short-circuit.
	p := newCancellablePhaser(ctx, 10*time.Second)

	done := make(chan struct{})
	start := time.Now()
	go func() {
		p.Start()
		close(done)
	}()

	// First phase should still go out before we cancel.
	select {
	case got := <-p.NextPhase():
		require.Equal(t, dkg.DealPhase, got)
	case <-time.After(time.Second):
		t.Fatal("DealPhase not emitted before cancel")
	}

	cancel()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not return within 1s of ctx cancel")
	}

	require.Less(t, time.Since(start), 2*time.Second, "cancel path must beat the 30s TimePhaser cadence")

	// FinishPhase must be queued so kyber Protocol.Start exits on next read.
	var sawFinish bool
	for {
		select {
		case ph := <-p.NextPhase():
			if ph == dkg.FinishPhase {
				sawFinish = true
			}
		default:
			require.True(t, sawFinish, "FinishPhase must be enqueued on cancel to wind kyber down")
			return
		}
	}
}

func TestCancellablePhaser_CancelBeforeStart(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithCancel(t.Context())
	cancel()

	p := newCancellablePhaser(ctx, 10*time.Second)
	done := make(chan struct{})
	go func() {
		p.Start()
		close(done)
	}()

	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Start did not return when ctx was pre-cancelled")
	}

	select {
	case ph := <-p.NextPhase():
		require.Equal(t, dkg.FinishPhase, ph, "pre-cancelled Start should still emit FinishPhase")
	default:
		t.Fatal("FinishPhase not enqueued for pre-cancelled ctx")
	}
}
