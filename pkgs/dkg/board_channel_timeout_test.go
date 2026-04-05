package dkg

import (
	"context"
	"testing"
	"time"

	kyber_dkg "github.com/drand/kyber/share/dkg"
	"github.com/stretchr/testify/require"

	"github.com/ssvlabs/ssv-dkg/pkgs/board"
)

func TestLocalOwner_SendDealBundle_TimesOut(t *testing.T) {
	o := &LocalOwner{
		board: &board.Board{
			DealC:          make(chan kyber_dkg.DealBundle),
			ResponseC:      make(chan kyber_dkg.ResponseBundle),
			JustificationC: make(chan kyber_dkg.JustificationBundle),
		},
		boardChanTimeout: 10 * time.Millisecond,
	}

	err := o.sendDealBundle(kyber_dkg.DealBundle{})
	require.Error(t, err)
	require.ErrorIs(t, err, context.DeadlineExceeded)
}
