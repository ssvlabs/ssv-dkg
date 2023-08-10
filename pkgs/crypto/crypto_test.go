package crypto

import (
	"errors"
	"fmt"
	"testing"
	"time"

	"github.com/drand/kyber"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	kyberbls "github.com/drand/kyber/sign/bls"
	"github.com/drand/kyber/sign/tbls"
	"github.com/drand/kyber/util/random"
	"github.com/herumi/bls-eth-go-binary/bls"
	clock "github.com/jonboulle/clockwork"
	"github.com/stretchr/testify/require"
)

func TestDKGFull(t *testing.T) {
	n := 4
	thr := n - 1
	suite := kyber_bls12381.NewBLS12381Suite()
	tns := GenerateTestNodes(suite.G1().(dkg.Suite), n)
	list := NodesFromTest(tns)
	conf := dkg.Config{
		Suite:     suite.G1().(dkg.Suite),
		NewNodes:  list,
		Threshold: thr,
		Auth:      kyberbls.NewSchemeOnG2(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResults(t, suite.G1().(dkg.Suite), thr, n, results)
}

type TestNode struct {
	Index   uint32
	Private kyber.Scalar
	Public  kyber.Point
	dkg     *dkg.DistKeyGenerator
	res     *dkg.Result
	proto   *dkg.Protocol
	phaser  *dkg.TimePhaser
	board   *TestBoard
	clock   clock.FakeClock
}

func NewTestNode(s dkg.Suite, index int) *TestNode {
	private := s.Scalar().Pick(random.New())
	public := s.Point().Mul(private, nil)
	return &TestNode{
		Index:   uint32(index),
		Private: private,
		Public:  public,
	}
}

func GenerateTestNodes(s dkg.Suite, n int) []*TestNode {
	tns := make([]*TestNode, n)
	for i := 0; i < n; i++ {
		tns[i] = NewTestNode(s, i)
	}
	return tns
}

func NodesFromTest(tns []*TestNode) []dkg.Node {
	nodes := make([]dkg.Node, len(tns))
	for i := 0; i < len(tns); i++ {
		nodes[i] = dkg.Node{
			Index:  tns[i].Index,
			Public: tns[i].Public,
		}
	}
	return nodes
}

// inits the dkg structure
func SetupNodes(nodes []*TestNode, c *dkg.Config) {
	nonce := dkg.GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		dkg, err := dkg.NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func SetupReshareNodes(nodes []*TestNode, c *dkg.Config, coeffs []kyber.Point) {
	nonce := dkg.GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		if n.res != nil {
			c2.Share = n.res.Key
		} else {
			c2.PublicCoeffs = coeffs
		}
		dkg, err := dkg.NewDistKeyHandler(&c2)
		if err != nil {
			panic(err)
		}
		n.dkg = dkg
	}
}

func IsDealerIncluded(bundles []*dkg.ResponseBundle, dealer uint32) bool {
	for _, bundle := range bundles {
		for _, resp := range bundle.Responses {
			if resp.DealerIndex == dealer {
				return true
			}
		}
	}
	return false
}

func testResults(t *testing.T, suite dkg.Suite, thr, n int, results []*dkg.Result) {
	// test if all results are consistent
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite, shares, thr, n)
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite, shares, thr, n)
	require.NoError(t, err)
	public := suite.Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

	// Test Threshold Kyber message signing
	scheme := tbls.NewThresholdSchemeOnG2(kyber_bls12381.NewBLS12381Suite())
	sigShares := make([][]byte, 0)
	for _, x := range shares {
		sig, err := scheme.Sign(x, []byte("Hello World!"))
		require.Nil(t, err)
		require.Nil(t, scheme.VerifyPartial(exp, []byte("Hello World!"), sig))
		idx, err := scheme.IndexOf(sig)
		require.NoError(t, err)
		require.Equal(t, x.I, idx)
		sigShares = append(sigShares, sig)
		idx, err = scheme.IndexOf(sig)
		require.NoError(t, err)
		require.Equal(t, idx, x.I)
	}

	sig, err := scheme.Recover(exp, []byte("Hello World!"), sigShares, thr, n)
	require.Nil(t, err)
	err = scheme.VerifyRecovered(exp.Commit(), []byte("Hello World!"), sig)
	require.Nil(t, err)
}

type MapDeal func([]*dkg.DealBundle) []*dkg.DealBundle
type MapResponse func([]*dkg.ResponseBundle) []*dkg.ResponseBundle
type MapJustif func([]*dkg.JustificationBundle) []*dkg.JustificationBundle

func RunDKG(t *testing.T, tns []*TestNode, conf dkg.Config,
	dm MapDeal, rm MapResponse, jm MapJustif) []*dkg.Result {

	SetupNodes(tns, &conf)
	var deals []*dkg.DealBundle
	for _, node := range tns {
		d, err := node.dkg.Deals()
		require.NoError(t, err)
		deals = append(deals, d)
	}

	if dm != nil {
		deals = dm(deals)
	}

	var respBundles []*dkg.ResponseBundle
	for _, node := range tns {
		resp, err := node.dkg.ProcessDeals(deals)
		require.NoError(t, err)
		if resp != nil {
			respBundles = append(respBundles, resp)
		}
	}

	if rm != nil {
		respBundles = rm(respBundles)
	}

	var justifs []*dkg.JustificationBundle
	var results []*dkg.Result
	for _, node := range tns {
		res, just, err := node.dkg.ProcessResponses(respBundles)
		if !errors.Is(err, dkg.ErrEvicted) {
			// there should not be any other error than eviction
			require.NoError(t, err)
		}
		if res != nil {
			results = append(results, res)
		} else if just != nil {
			justifs = append(justifs, just)
		}
	}

	if len(justifs) == 0 {
		return results
	}

	if jm != nil {
		justifs = jm(justifs)
	}

	for _, node := range tns {
		res, err := node.dkg.ProcessJustifications(justifs)
		if errors.Is(err, dkg.ErrEvicted) {
			continue
		}
		require.NoError(t, err)
		require.NotNil(t, res)
		results = append(results, res)
	}
	return results
}

type TestNetwork struct {
	boards []*TestBoard
	noops  []uint32
}

func NewTestNetwork(n int) *TestNetwork {
	t := &TestNetwork{}
	for i := 0; i < n; i++ {
		t.boards = append(t.boards, NewTestBoard(uint32(i), n, t))
	}
	return t
}

func (n *TestNetwork) SetNoop(index uint32) {
	n.noops = append(n.noops, index)
}

func (n *TestNetwork) BoardFor(index uint32) *TestBoard {
	for _, b := range n.boards {
		if b.index == index {
			return b
		}
	}
	panic("no such indexes")
}

func (n *TestNetwork) isNoop(i uint32) bool {
	for _, j := range n.noops {
		if i == j {
			return true
		}
	}
	return false
}

func (n *TestNetwork) BroadcastDeal(a *dkg.DealBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newDeals <- (*a)
		}
	}
}

func (n *TestNetwork) BroadcastResponse(a *dkg.ResponseBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newResps <- *a
		}
	}
}

func (n *TestNetwork) BroadcastJustification(a *dkg.JustificationBundle) {
	for _, board := range n.boards {
		if !n.isNoop(board.index) {
			board.newJusts <- *a
		}
	}
}

type TestBoard struct {
	index    uint32
	newDeals chan dkg.DealBundle
	newResps chan dkg.ResponseBundle
	newJusts chan dkg.JustificationBundle
	network  *TestNetwork
	badDeal  bool
	badSig   bool
}

func NewTestBoard(index uint32, n int, network *TestNetwork) *TestBoard {
	return &TestBoard{
		network:  network,
		index:    index,
		newDeals: make(chan dkg.DealBundle, n),
		newResps: make(chan dkg.ResponseBundle, n),
		newJusts: make(chan dkg.JustificationBundle, n),
	}
}

func (t *TestBoard) PushDeals(d *dkg.DealBundle) {
	if t.badDeal {
		d.Deals[0].EncryptedShare = []byte("bad bad bad")
	}
	if t.badSig {
		d.Signature = []byte("bad signature my friend")
	}
	t.network.BroadcastDeal(d)
}

func (t *TestBoard) PushResponses(r *dkg.ResponseBundle) {
	t.network.BroadcastResponse(r)
}

func (t *TestBoard) PushJustifications(j *dkg.JustificationBundle) {
	t.network.BroadcastJustification(j)
}

func (t *TestBoard) IncomingDeal() <-chan dkg.DealBundle {
	return t.newDeals
}

func (t *TestBoard) IncomingResponse() <-chan dkg.ResponseBundle {
	return t.newResps
}

func (t *TestBoard) IncomingJustification() <-chan dkg.JustificationBundle {
	return t.newJusts
}

// func SetupProto(tns []*TestNode, dkgC *dkg.Config, period time.Duration, network *TestNetwork) {
// 	for _, n := range tns {
// 		clock := clock.NewFakeClock()
// 		n.clock = clock
// 		n.phaser = dkg.NewTimePhaserFunc(func(dkg.Phase) {
// 			clock.Sleep(period)
// 		})
// 		n.board = network.BoardFor(n.Index)
// 		c2 := *n.dkg.c
// 		proto, err := dkg.NewProtocol(&c2, n.board, n.phaser, false)
// 		if err != nil {
// 			panic(err)
// 		}
// 		n.proto = proto
// 	}
// }

func moveTime(tns []*TestNode, p time.Duration) {
	for _, node := range tns {
		node.clock.Advance(p)
	}
}

func TestDKGKyberToBLS(t *testing.T) {
	n := 4
	thr := n - 1
	suite := kyber_bls12381.NewBLS12381Suite()
	tns := GenerateTestNodes(suite.G1().(dkg.Suite), n)
	list := NodesFromTest(tns)
	conf := dkg.Config{
		Suite:     suite.G1().(dkg.Suite),
		NewNodes:  list,
		Threshold: thr,
		Auth:      kyberbls.NewSchemeOnG2(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResultsKyberToBLS(t, suite.G1().(dkg.Suite), thr, n, results)
}

func testResultsKyberToBLS(t *testing.T, suite dkg.Suite, thr, n int, results []*dkg.Result) {
	// test if all results are consistent
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite, shares, thr, n)
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite, shares, thr, n)
	require.NoError(t, err)
	public := suite.Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

	// Test Threshold Kyber message signing
	scheme := tbls.NewThresholdSchemeOnG2(kyber_bls12381.NewBLS12381Suite())
	sigShares := make([][]byte, 0)
	for _, x := range shares {
		sig, err := scheme.Sign(x, []byte("Hello World!"))
		require.Nil(t, err)
		require.Nil(t, scheme.VerifyPartial(exp, []byte("Hello World!"), sig))
		idx, err := scheme.IndexOf(sig)
		require.NoError(t, err)
		require.Equal(t, x.I, idx)
		sigShares = append(sigShares, sig)
		idx, err = scheme.IndexOf(sig)
		require.NoError(t, err)
		require.Equal(t, idx, x.I)
	}

	sig, err := scheme.Recover(exp, []byte("Hello World!"), sigShares, thr, n)
	require.Nil(t, err)
	err = scheme.VerifyRecovered(exp.Commit(), []byte("Hello World!"), sig)
	require.Nil(t, err)
	t.Logf("Kyber DKG signature %x", sig)

	// Try to deserialize Kyber recovered signature to BLS signature
	masterSig := &bls.Sign{}
	err = masterSig.Deserialize(sig)
	require.NoError(t, err)
	// test public key is recoverable to BLS library
	validatorPubKey, err := ResultsToValidatorPK(results[0].Key.Commitments(), suite)
	require.NoError(t, err)
	require.NotEmpty(t, validatorPubKey.Serialize())
	t.Logf("Pub key bytes %x", validatorPubKey.Serialize())
	res := masterSig.VerifyByte(validatorPubKey, []byte("Hello World!"))
	require.True(t, res)

	// Try to reconstruct BLS sig from Kyber partial sigs
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	reconstructedSig := bls.Sign{}
	for _, res := range results {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", res.Key.Share.I))
		require.NoError(t, err)
		idVec = append(idVec, blsID)

		priv, err := ResultToShareSecretKey(res)
		require.NoError(t, err)
		blsSig := priv.SignByte([]byte("Hello World!"))
		sigVec = append(sigVec, *blsSig)
	}
	err = reconstructedSig.Recover(sigVec, idVec)
	require.NoError(t, err)
	t.Logf("BLS reconstructed signature %x", sig)

	// Verify aggregated sig
	res = reconstructedSig.VerifyByte(validatorPubKey, []byte("Hello World!"))
	require.True(t, res)
}

func TestDKGKyberToBLSLowLevel(t *testing.T) {
	n := 4
	thr := n - 1
	suite := kyber_bls12381.NewBLS12381Suite()
	tns := GenerateTestNodes(suite.G1().(dkg.Suite), n)
	list := NodesFromTest(tns)
	conf := dkg.Config{
		Suite:     suite.G1().(dkg.Suite),
		NewNodes:  list,
		Threshold: thr,
		Auth:      kyberbls.NewSchemeOnG2(suite),
	}

	results := RunDKG(t, tns, conf, nil, nil, nil)
	testResultsKyberToBLSLowLevel(t, suite.G1().(dkg.Suite), thr, n, results)
}

func testResultsKyberToBLSLowLevel(t *testing.T, suite dkg.Suite, thr, n int, results []*dkg.Result) {
	// test if all results are consistent
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite, shares, thr, n)
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite, shares, thr, n)
	require.NoError(t, err)
	public := suite.Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

	// Go here to low level operations at poly and the group

}
