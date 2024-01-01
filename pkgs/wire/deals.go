package wire

import (
	"encoding/hex"
	"encoding/json"

	"github.com/drand/kyber"
	"github.com/drand/kyber/share/dkg"
)

type encodedDeals struct {
	Deal   *dkg.DealBundle
	Public []string
}

// EncodeDealBundle encodes a DKG deal bundle
func EncodeDealBundle(bundle *dkg.DealBundle) ([]byte, error) {
	var publics []string
	for _, p := range bundle.Public {
		byts, err := p.MarshalBinary()
		if err != nil {
			return nil, err
		}
		publics = append(publics, hex.EncodeToString(byts))
	}
	obj := &encodedDeals{
		Deal: &dkg.DealBundle{
			DealerIndex: bundle.DealerIndex,
			Deals:       bundle.Deals,
			SessionID:   bundle.SessionID,
			Signature:   bundle.Signature,
		},
		Public: publics,
	}

	return json.MarshalIndent(obj, "", " ")
}

// EncodeDealBundle decodes a DKG deal bundle
func DecodeDealBundle(byts []byte, suite dkg.Suite) (*dkg.DealBundle, error) {
	obj := &encodedDeals{}
	if err := json.Unmarshal(byts, &obj); err != nil {
		return nil, err
	}

	var publics []kyber.Point
	for _, p := range obj.Public {
		byts, err := hex.DecodeString(p)
		if err != nil {
			return nil, err
		}

		point := suite.Point()
		if err := point.UnmarshalBinary(byts); err != nil {
			return nil, err
		}
		publics = append(publics, point)
	}
	obj.Deal.Public = publics

	return obj.Deal, nil
}
