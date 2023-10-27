package dkg

import (
	"crypto/rand"
	"crypto/rsa"
	mrand "math/rand"
	"testing"

	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/drand/kyber"
	kyber_bls "github.com/drand/kyber-bls12381"
	"github.com/ethereum/go-ethereum/common"
	herumi_bls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	wire2 "github.com/bloxapp/ssv-dkg/pkgs/wire"
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
	T            *testing.T
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

func (ts *testState) ForOld(f func(o *LocalOwner) error, oldOps []*wire2.Operator) error {
	for _, op := range oldOps {
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
		Exchanges: make(map[uint64]*wire2.Exchange),
		BroadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		SignFunc:    sign,
		VerifyFunc:  ver,
		EncryptFunc: encrypt,
		DecryptFunc: decrypt,
		RSAPub:      &pv.PublicKey,
		Done:        make(chan struct{}, 1),
		StartedDKG:  make(chan struct{}, 1),
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
	opsarr := make([]*wire2.Operator, 0, len(ts.ops))
	for id, _ := range ts.ops {
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
		<-o.StartedDKG
		return nil
	})

	require.NoError(t, err)

	pubs := make(map[uint64]kyber.Point)
	err = ts.ForAll(func(o *LocalOwner) error {
		<-o.Done
		pubs[o.ID] = o.SecretShare.Public()
		return nil
	})
	require.NoError(t, err)

	secretsNodes := make(map[uint64]*herumi_bls.SecretKey)
	err = ts.ForAll(func(o *LocalOwner) error {
		key, err := crypto.KyberShareToBLSKey(o.SecretShare.PriShare())
		if err != nil {
			return nil
		}
		secretsNodes[o.ID] = key
		return nil
	})
	require.NoError(t, err)

	// check nodes sigs
	bytesToSign := []byte("Hello World")
	nodesSigs := make(map[uint64][]byte)
	sharePks := make(map[uint64]*herumi_bls.PublicKey)
	for id, n := range secretsNodes {
		sharePks[id] = n.GetPublicKey()
		sig := n.SignByte(bytesToSign)
		nodesSigs[id] = sig.Serialize()
	}
	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(sharePks)
	require.NoError(t, err)
	reconstructedMasterSig, err := crypto.ReconstructSignatures(nodesSigs)
	require.NoError(t, err)
	err = crypto.VerifyReconstructedSignature(reconstructedMasterSig, validatorRecoveredPK.Serialize(), bytesToSign)
	require.NoError(t, err)
}
