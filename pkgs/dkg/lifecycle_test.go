package dkg

import (
	"context"
	"crypto/rsa"
	"sort"
	"sync"
	"testing"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/goleak"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	wire2 "github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

func TestCloseDoneIdempotent(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	owner := New(t.Context(), &OwnerOpts{Logger: zap.NewNop()})

	owner.closeDone()
	select {
	case <-owner.done:
	default:
		t.Fatal("done channel not closed after first closeDone()")
	}

	// Subsequent calls must not panic on double-close.
	require.NotPanics(t, owner.closeDone)
	require.NotPanics(t, owner.closeDone)
}

func TestCloseDoneConcurrent(t *testing.T) {
	defer goleak.VerifyNone(t, goleak.IgnoreCurrent())

	owner := New(t.Context(), &OwnerOpts{Logger: zap.NewNop()})

	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			owner.closeDone()
		}()
	}
	wg.Wait()

	select {
	case <-owner.done:
	case <-time.After(time.Second):
		t.Fatal("done channel not closed after concurrent closeDone calls")
	}
}

func TestNewStoresSuppliedCtx(t *testing.T) {
	ctx := t.Context()
	owner := New(ctx, &OwnerOpts{Logger: zap.NewNop()})
	require.Same(t, ctx, owner.ctx)
}

func TestDKGCancelReleasesKyberGoroutines(t *testing.T) {
	// goleak.VerifyNone is the authoritative check; runtime.NumGoroutine
	// pre-bound was removed because it picks up runtime-internal goroutines
	// whose counts fluctuate under -race CI and produced flakes without
	// adding signal.
	ignore := goleak.IgnoreCurrent()

	_, initiatorPk, err := spec_crypto.GenerateRSAKeys()
	require.NoError(t, err)

	ctx, cancel := context.WithCancel(t.Context())
	ts := &testState{
		T:       t,
		ops:     make(map[uint64]*LocalOwner),
		opsPriv: make(map[uint64]*rsa.PrivateKey),
		tv:      newTestVerify(),
		ipk:     initiatorPk,
		results: make(map[uint64][]*spec.Result),
	}
	const numOps = 4
	for i := 1; i <= numOps; i++ {
		op, priv := NewTestOperatorWithCtx(ts, uint64(i), ctx) //nolint:gosec // test values
		ts.ops[op.ID] = op
		ts.opsPriv[op.ID] = priv
	}

	opsarr := make([]*spec.Operator, 0, numOps)
	for id := range ts.ops {
		pk, err := spec_crypto.EncodeRSAPublicKey(ts.tv.ops[id])
		require.NoError(t, err)
		opsarr = append(opsarr, &spec.Operator{ID: id, PubKey: pk})
	}
	sort.SliceStable(opsarr, func(i, j int) bool { return opsarr[i].ID < opsarr[j].ID })

	init := &spec.Init{
		Operators:             opsarr,
		T:                     3,
		WithdrawalCredentials: spec_crypto.WithdrawalCredentials(spec_crypto.ETH1WithdrawalPrefix, common.HexToAddress("0x1234")),
		Fork:                  [4]byte{0, 0, 0, 0},
		Nonce:                 0,
		Owner:                 common.HexToAddress("0x1234"),
		Amount:                uint64(spec_crypto.MIN_ACTIVATION_BALANCE),
	}

	uid := spec.NewID()
	exch := map[uint64]*wire2.Transport{}
	require.NoError(t, ts.ForAll(func(o *LocalOwner) error {
		tr, err := o.Init(uid, init)
		exch[o.ID] = tr
		return err
	}))
	require.NoError(t, ts.ForAll(func(o *LocalOwner) error {
		return o.Broadcast(exch[o.ID])
	}))
	require.NoError(t, ts.ForAll(func(o *LocalOwner) error {
		<-o.startedDKG
		return nil
	}))

	cancel()

	// goleak will retry internally for a short window to let goroutines drain.
	goleak.VerifyNone(t, ignore)
}
