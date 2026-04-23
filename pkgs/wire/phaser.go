package wire

import (
	"context"
	"time"

	"github.com/drand/kyber/share/dkg"
)

// cancellablePhaser is a dkg.Phaser that emits phases on a fixed cadence but
// exits when ctx is cancelled, enqueueing FinishPhase so kyber's Protocol.Start
// loop can observe it and return.
type cancellablePhaser struct {
	ctx   context.Context
	out   chan dkg.Phase
	sleep time.Duration
}

func newCancellablePhaser(ctx context.Context, sleep time.Duration) *cancellablePhaser {
	return &cancellablePhaser{
		ctx:   ctx,
		out:   make(chan dkg.Phase, 4), // matches kyber's default TimePhaser buffer
		sleep: sleep,
	}
}

func (p *cancellablePhaser) NextPhase() chan dkg.Phase {
	return p.out
}

// Start runs the phase progression in the calling goroutine. On ctx cancel it
// enqueues FinishPhase (best-effort) and returns.
func (p *cancellablePhaser) Start() {
	signalFinish := func() {
		select {
		case p.out <- dkg.FinishPhase:
		default:
		}
	}
	// Once cancelled, only FinishPhase may go out — never a real phase.
	send := func(ph dkg.Phase) bool {
		select {
		case <-p.ctx.Done():
			signalFinish()
			return false
		default:
		}
		select {
		case p.out <- ph:
			return true
		case <-p.ctx.Done():
			signalFinish()
			return false
		}
	}
	wait := func() bool {
		if p.sleep <= 0 {
			return true
		}
		select {
		case <-p.ctx.Done():
			signalFinish()
			return false
		default:
		}
		t := time.NewTimer(p.sleep)
		defer t.Stop()
		select {
		case <-t.C:
			return true
		case <-p.ctx.Done():
			signalFinish()
			return false
		}
	}

	if !send(dkg.DealPhase) {
		return
	}
	if !wait() {
		return
	}
	if !send(dkg.ResponsePhase) {
		return
	}
	if !wait() {
		return
	}
	if !send(dkg.JustifPhase) {
		return
	}
	if !wait() {
		return
	}
	send(dkg.FinishPhase)
}
