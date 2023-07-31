package dkg

import (
	"crypto/rsa"
	"fmt"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	wire2 "github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	bls "github.com/drand/kyber-bls12381"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	mrand "math/rand"
	"testing"
)

type testVerify struct {
	ops map[uint64]*rsa.PublicKey
	//mtx sync.Mutex
}

func newTestVerify() *testVerify {
	return &testVerify{
		ops: make(map[uint64]*rsa.PublicKey),
		//mtx: sync.Mutex{},
	}
}

func (tv *testVerify) Add(id uint64, pk *rsa.PublicKey) {
	//tv.mtx.Lock()
	tv.ops[id] = pk
	//tv.mtx.Unlock()
}

func (tv *testVerify) Verify(id uint64, msg, sig []byte) error {
	//tv.mtx.Lock()
	op, ok := tv.ops[id]
	if !ok {
		panic("test shouldn't do this")
	}
	//tv.mtx.Unlock()
	return crypto.VerifyRSA(op, msg, sig)
}

type testState struct {
	globalLogger *logrus.Entry
	T            *testing.T
	info         map[uint64]rsa.PublicKey
	ops          map[uint64]*LocalOwner
	tv           *testVerify
}

func (ts *testState) Broadcast(id uint64, data []byte) error {
	return ts.ForAll(func(o *LocalOwner) error {
		//if o.info.ID != id {
		st := &wire2.SignedTransport{}
		if err := st.UnmarshalSSZ(data); err != nil {
			return err
		}
		if err := o.Process(id, st); err != nil {
			return err
		}
		//}
		return nil
	})
}

func (ts *testState) ForAll(f func(o *LocalOwner) error) error {
	for _, op := range ts.ops {
		if err := f(op); err != nil {
			return err
		}
	}
	return nil
}

func NewTestOperator(ts *testState) *LocalOwner {
	id := mrand.Uint64()
	_, exists := ts.ops[id]
	for exists {
		id = mrand.Uint64()
		_, exists = ts.ops[id]
	}
	pv, pk, err := crypto.GenerateKeys()
	if err != nil {
		ts.T.Error(err)
	}

	ts.tv.Add(id, pk)

	sign := func(d []byte) ([]byte, error) {
		return crypto.SignRSA(pv, d)
	}

	ver := ts.tv.Verify

	return &LocalOwner{
		Logger:    logrus.NewEntry(logrus.New()).WithField("id", id),
		ID:        id,
		suite:     bls.NewBLS12381Suite(),
		Exchanges: make(map[uint64]*wire2.Exchange),
		BroadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		SignFunc:   sign,
		VerifyFunc: ver,
		done:       make(chan struct{}, 1),
		startedDKG: make(chan struct{}, 1),
	}

}

func TestDKG(t *testing.T) {
	// Send operators we want to deal with them

	n := 4

	ts := &testState{
		T:   t,
		ops: make(map[uint64]*LocalOwner),
		tv:  newTestVerify(),
	}

	for i := 0; i < n; i++ {
		op := NewTestOperator(ts)
		ts.ops[op.ID] = op
	}

	req := wire2.GetRandRequestID()

	//ops := make(map[uint64]Operator, len(ts.ops))
	opsarr := make([]*wire2.Operator, 0, len(ts.ops))

	for id, _ := range ts.ops {
		//ops[id] = own.info
		pktobytes, err := crypto.EncodePublicKey(ts.tv.ops[id])
		require.NoError(t, err)
		opsarr = append(opsarr, &wire2.Operator{
			ID:     id,
			Pubkey: pktobytes,
		})
	}

	init := &wire2.Init{
		Operators:             opsarr,
		T:                     3,
		WithdrawalCredentials: []byte("0x0000"),
		Fork:                  [4]byte{0, 0, 0, 0},
	}

	exch := map[uint64]*wire2.Transport{}

	err := ts.ForAll(func(o *LocalOwner) error {
		ts, err := o.Init(req, init)
		if err != nil {
			t.Error(t, err)
		}
		exch[o.ID] = ts
		return nil
	})

	err = ts.ForAll(func(o *LocalOwner) error {
		return o.Broadcast(exch[o.ID])
	})

	if err != nil {
		t.Error(err)
	}

	err = ts.ForAll(func(o *LocalOwner) error {
		<-o.done
		return nil
	})

	require.NoError(t, err)

}

func TestForALL(t *testing.T) {
	n := 4

	ts := &testState{
		T:   t,
		ops: make(map[uint64]*LocalOwner),
	}

	for i := 0; i < n; i++ {
		op := NewTestOperator(ts)
		ts.ops[op.ID] = op
	}

	//req := wire.GetRandRequestID()

	//ops := make(map[uint64]Operator, len(ts.ops))
	//
	//for id, own := range ts.ops {
	//	ops[id] = own.info
	//}

	require.Len(t, ts.ops, n)
	//require.Len(t, ops, n)

	c := make(chan uint64, n)

	err := ts.ForAll(func(o *LocalOwner) error {
		c <- o.ID
		return nil
	})

	require.NoError(t, err)

	for i := 0; i < n; i++ {
		fmt.Println(<-c)
	}

}
