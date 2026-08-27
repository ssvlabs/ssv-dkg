package operator

import (
	"context"
	"fmt"
	"sync/atomic"
	"testing"
	"time"

	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"

	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

type trackedInstance struct {
	closed atomic.Bool
}

func (t *trackedInstance) ProcessMessages(*wire.MultipleSignedTransports) ([]byte, error) {
	return nil, fmt.Errorf("not used in test: %w", context.DeadlineExceeded)
}

func (t *trackedInstance) VerifyInitiatorMessage([]byte, []byte) error { return nil }

func (t *trackedInstance) Close() { t.closed.Store(true) }

func TestCleanInstancesClosesExpired(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	var liveID, expiredID InstanceID
	copy(liveID[:], "live-instance-id-01234567")
	copy(expiredID[:], "expired-instance-01234567")

	live := &trackedInstance{}
	expired := &trackedInstance{}

	s := &Switch{
		Instances: map[InstanceID]Instance{liveID: live, expiredID: expired},
		InstanceInitTime: map[InstanceID]time.Time{
			liveID:    time.Now(),
			expiredID: time.Now().Add(-2 * MaxInstanceTime),
		},
	}

	count := s.cleanInstances()
	require.Equal(t, 1, count)
	require.False(t, live.closed.Load(), "live instance must not be closed")
	require.True(t, expired.closed.Load(), "expired instance must be closed")
	require.Len(t, s.Instances, 1)
	_, stillThere := s.Instances[liveID]
	require.True(t, stillThere)
}

func TestValidateInstancesClosesCollidingExpired(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	var reqID InstanceID
	copy(reqID[:], "test-instance-id-0123456")

	expired := &trackedInstance{}
	s := &Switch{
		Instances:        map[InstanceID]Instance{reqID: expired},
		InstanceInitTime: map[InstanceID]time.Time{reqID: time.Now().Add(-2 * MaxInstanceTime)},
	}

	require.NoError(t, s.validateInstances(reqID))
	require.True(t, expired.closed.Load(), "expired colliding instance must be closed")
	require.Empty(t, s.Instances)
}

func TestInstWrapperCloseCancelsLifecycleCtx(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	ctx, cancel := context.WithCancel(t.Context())
	iw := &instWrapper{cancel: cancel}

	iw.Close()
	select {
	case <-ctx.Done():
		// expected
	case <-time.After(time.Second):
		t.Fatal("Close did not cancel the lifecycle context")
	}

	require.NotPanics(t, iw.Close)
	require.NotPanics(t, iw.Close)
}

func TestReaperSweepsExpiredInstancesAndStops(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	var expiredID, liveID InstanceID
	copy(expiredID[:], "expired-instance-01234567")
	copy(liveID[:], "live-instance-id-01234567")

	expired := &trackedInstance{}
	live := &trackedInstance{}

	s := &Switch{
		Instances: map[InstanceID]Instance{expiredID: expired, liveID: live},
		InstanceInitTime: map[InstanceID]time.Time{
			expiredID: time.Now().Add(-2 * MaxInstanceTime),
			liveID:    time.Now(),
		},
	}

	s.StartReaper(10 * time.Millisecond)
	defer s.StopReaper()

	require.Eventually(t, func() bool {
		s.Mtx.RLock()
		_, stillThere := s.Instances[expiredID]
		s.Mtx.RUnlock()
		return !stillThere
	}, time.Second, 20*time.Millisecond)

	require.True(t, expired.closed.Load())
	require.False(t, live.closed.Load())
	s.Mtx.RLock()
	_, liveStillThere := s.Instances[liveID]
	s.Mtx.RUnlock()
	require.True(t, liveStillThere)
}
