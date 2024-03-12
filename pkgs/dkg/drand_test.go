package dkg

import (
	"crypto/rand"
	"crypto/rsa"
	"fmt"
	"sort"
	"testing"

	kyber_bls "github.com/drand/kyber-bls12381"
	kyber_dkg "github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	herumi_bls "github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
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

func (tv *testVerify) Verify(id uint64, msg, sig []byte) error {
	op, ok := tv.ops[id]
	if !ok {
		return errors.New("test shouldn't do this")
	}
	return crypto.VerifyRSA(op, msg, sig)
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
		if err := o.Process(id, st); err != nil {
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
		deals:     make(map[uint64]*kyber_dkg.DealBundle),
		broadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		signFunc:           sign,
		verifyFunc:         ver,
		encryptFunc:        encrypt,
		decryptFunc:        decrypt,
		InitiatorPublicKey: ts.ipk,
		RSAPub:             &pv.PublicKey,
		done:               make(chan struct{}, 1),
		startedDKG:         make(chan struct{}, 1),
	}, pv
}

func AddExistingOperator(ts *testState, owner *LocalOwner) *LocalOwner {
	id := owner.ID
	ts.tv.Add(id, owner.RSAPub)
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
		deals:     make(map[uint64]*kyber_dkg.DealBundle),
		broadcastF: func(bytes []byte) error {
			return ts.Broadcast(id, bytes)
		},
		signFunc:           sign,
		verifyFunc:         ver,
		encryptFunc:        owner.encryptFunc,
		decryptFunc:        owner.decryptFunc,
		InitiatorPublicKey: ts.ipk,
		RSAPub:             owner.RSAPub,
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
	encodedInitiatorPk, err := crypto.EncodeRSAPublicKey(initatorPk)
	require.NoError(t, err)
	// sort ops
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
		InitiatorPublicKey:    encodedInitiatorPk,
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
	var encShares []byte
	var ceremonySigs []byte
	var pubkeys []byte
	ssvContractOwnerNonceSigShares := make([]*herumi_bls.Sign, 0)
	for i := 1; i < 5; i++ {
		encShare, ceremonySig, pubkey, sigOwnerNonce, err := constructShares(ts.ops[uint64(i)])
		require.NoError(t, err)
		encShares = append(encShares, encShare...)
		ceremonySigs = append(ceremonySigs, ceremonySig...)
		pubkeys = append(pubkeys, pubkey...)
		ssvContractOwnerNonceSigShares = append(ssvContractOwnerNonceSigShares, sigOwnerNonce)
	}
	var sharesData []byte
	sharesData = append(sharesData, pubkeys...)
	sharesData = append(sharesData, encShares...)
	reconstructedOwnerNonceMasterSig, err := crypto.RecoverBLSSignature(ids, ssvContractOwnerNonceSigShares)
	require.NoError(t, err)
	var sharesDataSigned []byte
	sharesDataSigned = append(sharesDataSigned, reconstructedOwnerNonceMasterSig.Serialize()...)
	sharesDataSigned = append(sharesDataSigned, sharesData...)
	for _, o := range ts.ops {
		_, err := crypto.GetSecretShareFromSharesData(sharesDataSigned, init.InitiatorPublicKey, ceremonySigs, opsarr, ts.opsPriv[o.ID], o.ID)
		require.NoError(t, err)
	}
}

func constructShares(o *LocalOwner) (encShare, ceremonySig, pubkey []byte, sigOwnerNonce *herumi_bls.Sign, err error) {
	key, err := crypto.KyberShareToBLSKey(o.SecretShare.PriShare())
	if err != nil {
		return nil, nil, nil, nil, err
	}
	// Encrypt BLS share for SSV contract
	ciphertext, err := o.encryptFunc([]byte(key.SerializeToHexStr()))
	if err != nil {
		return nil, nil, nil, nil, err
	}
	ceremonySig, err = o.GetCeremonySig(key)
	if err != nil {
		return nil, nil, nil, nil, err
	}
	pubkey = key.GetPublicKey().Serialize()
	data := []byte(fmt.Sprintf("%s:%d", o.owner.String(), o.nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	sigOwnerNonce = key.SignByte(hash)
	return ciphertext, ceremonySig, pubkey, sigOwnerNonce, nil
}
