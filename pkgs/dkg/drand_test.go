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
	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
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

type testState struct {
	T       *testing.T
	ops     map[uint64]*LocalOwner
	opsPriv map[uint64]*rsa.PrivateKey
	tv      *testVerify
	ipk     *rsa.PublicKey
	results map[uint64][]*spec.Result
}

func (ts *testState) Broadcast(id uint64, data []byte) error {
	return ts.ForAll(func(o *LocalOwner) error {
		st := &wire2.SignedTransport{}
		if err := st.UnmarshalSSZ(data); err != nil {
			return err
		}
		if st.Message.Type == wire2.OutputMessageType {
			res := &spec.Result{}
			err := res.UnmarshalSSZ(st.Message.Data)
			if err != nil {
				return err
			}
			ts.results[o.ID] = append(ts.results[o.ID], res)
			return nil
		}
		if err := o.Process(st, o.data.init.Operators); err != nil {
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

func NewTestOperator(ts *testState, id uint64) (*LocalOwner, *rsa.PrivateKey) {
	pv, pk, err := spec_crypto.GenerateRSAKeys()
	if err != nil {
		ts.T.Error(err)
	}
	ts.tv.Add(id, pk)
	encrypt := func(d []byte) ([]byte, error) {
		return rsa.EncryptPKCS1v15(rand.Reader, pk, d)
	}
	decrypt := func(d []byte) ([]byte, error) {
		return rsaencryption.DecodeKey(pv, d)
	}
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
		signer:             crypto.RSASigner(pv),
		encryptFunc:        encrypt,
		decryptFunc:        decrypt,
		InitiatorPublicKey: ts.ipk,
		OperatorSecretKey:  pv,
		done:               make(chan struct{}, 1),
		startedDKG:         make(chan struct{}, 1),
	}, pv
}

func TestDKGInit(t *testing.T) {
	// Send operators we want to deal with them
	_, initatorPk, err := spec_crypto.GenerateRSAKeys()
	require.NoError(t, err)
	ts := &testState{
		T:       t,
		ops:     make(map[uint64]*LocalOwner),
		opsPriv: make(map[uint64]*rsa.PrivateKey),
		tv:      newTestVerify(),
		ipk:     initatorPk,
		results: make(map[uint64][]*spec.Result, 0),
	}
	for i := 1; i < 5; i++ {
		op, priv := NewTestOperator(ts, uint64(i))
		ts.ops[op.ID] = op
		ts.opsPriv[op.ID] = priv
	}
	opsarr := make([]*spec.Operator, 0, len(ts.ops))
	for id := range ts.ops {
		pktobytes, err := spec_crypto.EncodeRSAPublicKey(ts.tv.ops[id])
		require.NoError(t, err)
		opsarr = append(opsarr, &spec.Operator{
			ID:     id,
			PubKey: pktobytes,
		})
	}
	sort.SliceStable(opsarr, func(i, j int) bool {
		return opsarr[i].ID < opsarr[j].ID
	})
	init := &spec.Init{
		Operators:             opsarr,
		T:                     3,
		WithdrawalCredentials: []byte("0x0000"),
		Fork:                  [4]byte{0, 0, 0, 0},
		Nonce:                 0,
		Owner:                 common.HexToAddress("0x1234"),
	}
	uid := spec.NewID()
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
	for _, res := range ts.results {
		validatorPK, err := spec.RecoverValidatorPKFromResults(res)
		require.NoError(t, err)
		_, _, _, err = spec.ValidateResults(opsarr, init.WithdrawalCredentials, validatorPK, init.Fork, init.Owner, init.Nonce, uid, res)
		require.NoError(t, err)
	}
}
