package crypto

import (
	"errors"
	"fmt"
	"testing"

	"github.com/drand/kyber"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	drand_bls "github.com/drand/kyber/sign/bls" //nolint:all
	"github.com/drand/kyber/sign/tbls"
	"github.com/drand/kyber/util/random"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/ssv-spec/types"
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
		Auth:      drand_bls.NewSchemeOnG2(suite),
	}
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)

	results := RunDKGKyberProtocol(t, tns, &conf, nil, nil, nil)
	testResults(t, suite, thr, n, results)
}

func testResults(t *testing.T, suite pairing.Suite, thr, n int, results []*dkg.Result) {
	// test if all results are consistent
	sharesBLS := make(map[types.OperatorID]*bls.SecretKey)
	valPK := &bls.PublicKey{}
	for i, res := range results {
		require.Equal(t, thr, len(res.Key.Commitments()))
		for j, res2 := range results {
			if i == j {
				continue
			}
			require.True(t, res.PublicEqual(res2), "res %+v != %+v", res, res2)
		}
		blsSecKey, err := ResultToShareSecretKey(res.Key)
		require.NoError(t, err)
		sharesBLS[uint64(res.Key.Share.I+1)] = blsSecKey
		valPK, err = ResultToValidatorPK(res.Key, suite.G1().(dkg.Suite))
		require.NoError(t, err)
	}
	// test if re-creating secret key gives same public key
	var shares []*share.PriShare
	for _, res := range results {
		shares = append(shares, res.Key.PriShare())
	}
	// test if shares are public polynomial evaluation
	exp := share.NewPubPoly(suite.G1(), suite.G1().Point().Base(), results[0].Key.Commitments())
	for _, share := range shares {
		pubShare := exp.Eval(share.I)
		expShare := suite.G1().Point().Mul(share.V, nil)
		require.True(t, pubShare.V.Equal(expShare), "share %s give pub %s vs exp %s", share.V.String(), pubShare.V.String(), expShare.String())
	}

	secretPoly, err := share.RecoverPriPoly(suite.G1(), shares, thr, n)
	coefs := secretPoly.Coefficients()
	t.Logf("Ploly len %d", len(coefs))
	for _, c := range coefs {
		t.Logf("Ploly coef %s", c.String())
	}
	require.NoError(t, err)
	gotPub := secretPoly.Commit(suite.G1().Point().Base())
	require.True(t, exp.Equal(gotPub))

	secret, err := share.RecoverSecret(suite.G1(), shares, thr, n)
	require.NoError(t, err)
	public := suite.G1().Point().Mul(secret, nil)
	expKey := results[0].Key.Public()
	require.True(t, public.Equal(expKey))

	// Test Threshold Kyber message signing
	scheme := tbls.NewThresholdSchemeOnG2(kyber_bls12381.NewBLS12381Suite())

	for _, x := range shares {
		sig, err := scheme.Sign(x, []byte("Hello World!"))
		require.Nil(t, err)
		require.Nil(t, scheme.VerifyPartial(exp, []byte("Hello World!"), sig))
		idx, err := scheme.IndexOf(sig)
		require.NoError(t, err)
		require.Equal(t, x.I, idx)
		idx, err = scheme.IndexOf(sig)
		require.NoError(t, err)
		require.Equal(t, idx, x.I)
	}
	// Compute bls sigs
	payloadToSign := "Hello World!"
	pks := make(map[types.OperatorID]*bls.PublicKey)
	sigs := make(map[types.OperatorID]*bls.Sign)
	for id, ps := range sharesBLS {
		pks[id] = ps.GetPublicKey()
		sigs[id] = ps.Sign(payloadToSign)
	}

	// get validator pk
	validatorPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for operatorID, pk := range pks {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", operatorID))
		require.NoError(t, err)
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *pk)
	}
	require.NoError(t, validatorPK.Recover(pkVec, idVec))
	require.Equal(t, validatorPK.Serialize(), valPK.Serialize())
	// reconstruct sig
	reconstructedSig := bls.Sign{}
	idVec = make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for operatorID, sig := range sigs {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", operatorID))
		require.NoError(t, err)
		idVec = append(idVec, blsID)

		sigVec = append(sigVec, *sig)

		if len(sigVec) >= thr {
			break
		}
	}
	require.NoError(t, reconstructedSig.Recover(sigVec, idVec))
	// verify
	require.True(t, reconstructedSig.Verify(&validatorPK, payloadToSign))
}

type TestNode struct {
	Index   uint32
	Private kyber.Scalar
	Public  kyber.Point
	dkg     *dkg.DistKeyGenerator
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
func SetupNodes(nodes []*TestNode, c *dkg.Config) error {
	nonce := dkg.GetNonce()
	for _, n := range nodes {
		c2 := *c
		c2.Longterm = n.Private
		c2.Nonce = nonce
		dkgProto, err := dkg.NewDistKeyHandler(&c2)
		if err != nil {
			return err
		}
		n.dkg = dkgProto
	}
	return nil
}

type MapDeal func([]*dkg.DealBundle) []*dkg.DealBundle
type MapResponse func([]*dkg.ResponseBundle) []*dkg.ResponseBundle
type MapJustif func([]*dkg.JustificationBundle) []*dkg.JustificationBundle

func RunDKGKyberProtocol(t *testing.T, tns []*TestNode, conf *dkg.Config,
	dm MapDeal, rm MapResponse, jm MapJustif) []*dkg.Result {

	err := SetupNodes(tns, conf)
	require.NoError(t, err)

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
