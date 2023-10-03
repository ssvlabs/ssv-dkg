package dkg

import (
	"context"
	"crypto/rsa"
	"fmt"
	mrand "math/rand"
	"testing"
	"time"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	wire2 "github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/storage/basedb"
	"github.com/bloxapp/ssv/storage/kv"
	"github.com/drand/kyber"
	bls "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"
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
func (ts *testState) ForNew(f func(o *LocalOwner) error, newOps []*wire2.Operator) error {
	for _, op := range newOps {
		newOp := ts.ops[op.ID]
		if err := f(newOp); err != nil {
			return err
		}
	}
	return nil
}

func NewTestOperator(ts *testState) *LocalOwner {
	id := uint64(mrand.Int63n(13))
	_, exists := ts.ops[id]
	for exists || id == 0 {
		id = uint64(mrand.Int63n(13))
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
	logger, _ := zap.NewDevelopment()
	logger = logger.With(zap.Uint64("id", id))
	db, err := kv.NewInMemory(logger, basedb.Options{
		Reporting: true,
		Ctx:       context.Background(),
		Path:      ts.T.TempDir(),
	})
	if err != nil {
		ts.T.Error(err)
	}
	return &LocalOwner{
		Logger:    logger,
		ID:        id,
		suite:     bls.NewBLS12381Suite(),
		Exchanges: make(map[uint64]*wire2.Exchange),
		Deals:     make(map[uint64]*dkg.DealBundle),
		BroadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		SignFunc:   sign,
		VerifyFunc: ver,
		OpPrivKey:  pv,
		done:       make(chan struct{}, 1),
		startedDKG: make(chan struct{}, 1),
		DB:         db,
	}
}

func AddExistingOperator(ts *testState, owner *LocalOwner) *LocalOwner {
	id := owner.ID
	pv, pk := owner.OpPrivKey, &owner.OpPrivKey.PublicKey
	ts.tv.Add(id, pk)

	sign := func(d []byte) ([]byte, error) {
		return crypto.SignRSA(pv, d)
	}

	ver := ts.tv.Verify

	logger, _ := zap.NewDevelopment()
	logger = logger.With(zap.Uint64("id", id))
	return &LocalOwner{
		Logger:    logger,
		ID:        id,
		suite:     bls.NewBLS12381Suite(),
		Exchanges: make(map[uint64]*wire2.Exchange),
		Deals:     make(map[uint64]*dkg.DealBundle),
		BroadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		SignFunc:   sign,
		VerifyFunc: ver,
		OpPrivKey:  pv,
		done:       make(chan struct{}, 1),
		startedDKG: make(chan struct{}, 1),
		DB:         owner.DB,
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

	//ops := make(map[uint64]Operator, len(ts.ops))
	opsarr := make([]*wire2.Operator, 0, len(ts.ops))

	for id, _ := range ts.ops {
		//ops[id] = own.info
		pktobytes, err := crypto.EncodePublicKey(ts.tv.ops[id])
		require.NoError(t, err)
		opsarr = append(opsarr, &wire2.Operator{
			ID:     id,
			PubKey: pktobytes,
		})
	}

	init := &wire2.Init{
		Operators:             opsarr,
		T:                     3,
		WithdrawalCredentials: []byte("0x0000"),
		Fork:                  [4]byte{0, 0, 0, 0},
		Nonce:                 0,
		Owner:                 common.HexToAddress("0x1234"),
	}
	uid := crypto.NewID()
	exch := map[uint64]*wire2.Transport{}

	err := ts.ForAll(func(o *LocalOwner) error {
		ts, err := o.Init(uid, init)
		if err != nil {
			t.Error(t, err)
		}
		exch[o.ID] = ts
		return nil
	})
	require.NoError(t, err)
	err = ts.ForAll(func(o *LocalOwner) error {
		return o.Broadcast(exch[o.ID])
	})
	require.NoError(t, err)
	err = ts.ForAll(func(o *LocalOwner) error {
		<-o.startedDKG
		return nil
	})

	require.NoError(t, err)

	pubs := make(map[uint64]kyber.Point)
	err = ts.ForAll(func(o *LocalOwner) error {
		<-o.done
		pubs[o.ID] = o.SecretShare.Public()
		return nil
	})
	require.NoError(t, err)
	var commits []kyber.Point
	err = ts.ForAll(func(o *LocalOwner) error {
		commits = o.SecretShare.Commits
		return nil
	})
	require.NoError(t, err)
	commitsbytes := make([]byte, 0, 48*3)
	fmt.Println("################ commits #####################################################################")
	for _, comm := range commits {
		bin, err := comm.MarshalBinary()
		require.NoError(t, err)
		fmt.Println(len(bin))
		commitsbytes = append(commitsbytes, bin...)
	}

	// Start resharing

	fmt.Println("###########################################################################################")
	fmt.Println("###########################################################################################")
	fmt.Println("###########################################################################################")
	fmt.Println("###########################################################################################")
	time.Sleep(1 * time.Second)
	fmt.Println("######################################START OF RESHARE#####################################################")
	fmt.Println("###########################################################################################")
	fmt.Println("###########################################################################################")
	fmt.Println("###########################################################################################")
	fmt.Println("###########################################################################################")

	ts2 := &testState{
		T:   t,
		ops: make(map[uint64]*LocalOwner),
		tv:  newTestVerify(),
	}

	for _, opx := range ts.ops {
		op := AddExistingOperator(ts2, opx)
		ts2.ops[op.ID] = op
	}

	var newops []uint64
	newopsArr := make([]*wire2.Operator, 0, len(ts2.tv.ops))
	//newopsArr = append(newopsArr, opsarr...)
	//spew.Dump(newopsArr)

	for i := 0; i < n; i++ {
		op := NewTestOperator(ts2)
		ts2.ops[op.ID] = op
		newops = append(newops, op.ID)
	}

	for _, opid := range newops {
		//ops[id] = own.info
		pktobytes, err := crypto.EncodePublicKey(ts2.tv.ops[opid])
		require.NoError(t, err)
		newopsArr = append(newopsArr, &wire2.Operator{
			ID:     opid,
			PubKey: pktobytes,
		})
	}

	fmt.Println("############################################## OPERATOPR ")
	fmt.Println("############################################## OLD OPERATOPR ")
	for _, i := range opsarr {
		fmt.Println(i.ID)
	}
	fmt.Println("############################################## NEW OPERATOPR ")
	for _, i := range newopsArr {
		fmt.Println(i.ID)
	}
	fmt.Println("############################################## OPERATOPR ")

	reshare := &wire2.Reshare{
		OldOperators: opsarr,
		NewOperators: newopsArr,
		OldID:        uid,
		OldT:         3,
		NewT:         6,
		Nonce:        0,
		Owner:        common.HexToAddress("0x1234"),
	}
	newuid := crypto.NewID()
	exch2 := map[uint64]*wire2.Transport{}

	err = ts2.ForAll(func(o *LocalOwner) error {
		var share *dkg.DistKeyShare
		if oldop, ex := ts.ops[o.ID]; ex {
			share = oldop.SecretShare
		}
		o.SecretShare = share
		var commits []byte
		for _, point := range o.SecretShare.Commits {
			b, _ := point.MarshalBinary()
			commits = append(commits, b...)
		}
		ts, err := o.CreateInstanceReshare(newuid, reshare, commits)
		if err != nil {
			t.Error(t, err)
		}
		exch2[o.ID] = ts
		return nil
	})
	require.NoError(t, err)
	err = ts2.ForAll(func(o *LocalOwner) error {
		return o.Broadcast(exch2[o.ID])
	})

	require.NoError(t, err)

	err = ts2.ForAll(func(o *LocalOwner) error {
		<-o.startedDKG
		return nil
	})

	require.NoError(t, err)
	newPubs := make(map[uint64]kyber.Point)
	err = ts2.ForAll(func(o *LocalOwner) error {
		<-o.done
		return nil
	})

	// Print old pubs
	var resPub kyber.Point
	for id, pub := range pubs {
		t.Logf("ID %d, old pub %s", id, pub.String())
		resPub = pub
	}
	// Print new pubs
	for id, pub := range newPubs {
		require.Equal(t, resPub.String(), pub.String())
		t.Logf("ID %d, new pub %s", id, pub.String())
	}
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
