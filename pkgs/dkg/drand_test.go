package dkg

import (
	"crypto/rand"
	"crypto/rsa"
	"sort"
	"testing"

	kyber_bls "github.com/drand/kyber-bls12381"
	"github.com/ethereum/go-ethereum/common"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	wire2 "github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

type testVerify struct {
	ops map[uint64]*rsa.PublicKey
}

func newTestVerify() *testVerify {
	return &testVerify{
		ops: make(map[uint64]*rsa.PublicKey),
	}
}

func (tv *testVerify) Add(id uint64, pk *rsa.PublicKey) {
	tv.ops[id] = pk
}

func (tv *testVerify) Verify(pub, msg, sig []byte) error {
	p, err := crypto.ParseRSAPublicKey(pub)
	if err != nil {
		return nil
	}
	return crypto.VerifyRSA(p, msg, sig)
}

type testState struct {
	T       *testing.T
	ops     map[uint64]*LocalOwner
	opsPriv map[uint64]*rsa.PrivateKey
	tv      *testVerify
	ipk     *rsa.PublicKey
}

func (ts *testState) Broadcast(id uint64, data []byte) error {
	return ts.ForAll(func(o *LocalOwner) error {
		st := &wire2.SignedTransport{}
		if err := st.UnmarshalSSZ(data); err != nil {
			return err
		}
		if err := o.Process(st); err != nil {
			return err
		}
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

func (ts *testState) ForOld(f func(o *LocalOwner) error, oldOps []*wire2.Operator) error {
	for _, op := range oldOps {
		newOp := ts.ops[op.ID]
		if err := f(newOp); err != nil {
			return err
		}
	}
	return nil
}

func NewTestOperator(ts *testState, id uint64) (*LocalOwner, *rsa.PrivateKey) {
	pv, pk, err := crypto.GenerateRSAKeys()
	if err != nil {
		ts.T.Error(err)
	}
	ts.tv.Add(id, pk)
	sign := func(d []byte) ([]byte, error) {
		return crypto.SignRSA(pv, d)
	}
	encrypt := func(d []byte) ([]byte, error) {
		return rsa.EncryptPKCS1v15(rand.Reader, pk, d)
	}
	decrypt := func(d []byte) ([]byte, error) {
		return rsaencryption.DecodeKey(pv, d)
	}
	ver := ts.tv.Verify
	logger, _ := zap.NewDevelopment()
	logger = logger.With(zap.Uint64("id", id))
	return &LocalOwner{
		Logger:    logger,
		ID:        id,
		Suite:     kyber_bls.NewBLS12381Suite(),
		exchanges: make(map[uint64]*wire2.Exchange),
		broadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		signFunc:           sign,
		verifyFunc:         ver,
		encryptFunc:        encrypt,
		decryptFunc:        decrypt,
		InitiatorPublicKey: ts.ipk,
		OperatorPublicKey:  &pv.PublicKey,
		done:               make(chan struct{}, 1),
		startedDKG:         make(chan struct{}, 1),
	}, pv
}

func AddExistingOperator(ts *testState, owner *LocalOwner) *LocalOwner {
	id := owner.ID
	ts.tv.Add(id, owner.OperatorPublicKey)
	sign := func(d []byte) ([]byte, error) {
		return owner.signFunc(d)
	}
	ver := ts.tv.Verify
	logger, _ := zap.NewDevelopment()
	logger = logger.With(zap.Uint64("id", id))
	return &LocalOwner{
		Logger:    logger,
		ID:        id,
		Suite:     kyber_bls.NewBLS12381Suite(),
		exchanges: make(map[uint64]*wire2.Exchange),
		broadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		signFunc:           sign,
		verifyFunc:         ver,
		encryptFunc:        owner.encryptFunc,
		decryptFunc:        owner.decryptFunc,
		InitiatorPublicKey: ts.ipk,
		OperatorPublicKey:  owner.OperatorPublicKey,
		done:               make(chan struct{}, 1),
		startedDKG:         make(chan struct{}, 1),
	}

}

func TestDKGInit(t *testing.T) {
	// Send operators we want to deal with them
	_, initatorPk, err := crypto.GenerateRSAKeys()
	require.NoError(t, err)
	ts := &testState{
		T:       t,
		ops:     make(map[uint64]*LocalOwner),
		opsPriv: make(map[uint64]*rsa.PrivateKey),
		tv:      newTestVerify(),
		ipk:     initatorPk,
	}
	var ids []uint64
	for i := 1; i < 5; i++ {
		op, priv := NewTestOperator(ts, uint64(i))
		ts.ops[op.ID] = op
		ts.opsPriv[op.ID] = priv
		ids = append(ids, op.ID)
	}
	opsarr := make([]*wire2.Operator, 0, len(ts.ops))
	for id := range ts.ops {
		pktobytes, err := crypto.EncodeRSAPublicKey(ts.tv.ops[id])
		require.NoError(t, err)
		opsarr = append(opsarr, &wire2.Operator{
			ID:     id,
			PubKey: pktobytes,
		})
	}
	sort.SliceStable(opsarr, func(i, j int) bool {
		return opsarr[i].ID < opsarr[j].ID
	})
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

	err = ts.ForAll(func(o *LocalOwner) error {
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
	err = ts.ForAll(func(o *LocalOwner) error {
		<-o.done
		return nil
	})
	require.NoError(t, err)
}
