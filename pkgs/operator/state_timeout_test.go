package operator

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

type timeoutInstance struct{}

func (timeoutInstance) ProcessMessages(*wire.MultipleSignedTransports) ([]byte, error) {
	return nil, fmt.Errorf("timed out: %w", context.DeadlineExceeded)
}

func (timeoutInstance) VerifyInitiatorMessage([]byte, []byte) error { return nil }

func (timeoutInstance) Close() {}

func TestProcessMessage_DeletesInstanceOnTimeout(t *testing.T) {
	var instanceID InstanceID
	copy(instanceID[:], "test-instance-id-0123456")

	s := &Switch{
		Instances:        map[InstanceID]Instance{instanceID: timeoutInstance{}},
		InstanceInitTime: map[InstanceID]time.Time{instanceID: time.Now()},
	}

	st := &wire.MultipleSignedTransports{Identifier: [24]byte(instanceID)}
	raw, err := st.MarshalSSZ()
	require.NoError(t, err)

	_, err = s.ProcessMessage(raw)
	require.Error(t, err)

	s.Mtx.RLock()
	_, ok := s.Instances[instanceID]
	s.Mtx.RUnlock()
	require.False(t, ok, "expected instance to be removed on timeout")
}
