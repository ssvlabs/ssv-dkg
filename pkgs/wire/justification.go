package wire

import (
	"encoding/hex"
	"encoding/json"

	"github.com/drand/kyber/share/dkg"
)

type encodedJustification struct {
	ShareIndex uint32
	Share      string
}

func encodeJustifications(justifications []dkg.Justification) ([]encodedJustification, error) {
	ret := make([]encodedJustification, 0)
	for _, j := range justifications {
		byts, err := j.Share.MarshalBinary()
		if err != nil {
			return nil, err
		}

		ret = append(ret, encodedJustification{
			ShareIndex: j.ShareIndex,
			Share:      hex.EncodeToString(byts),
		})
	}
	return ret, nil
}

func decodeJustifications(justifications []encodedJustification, suite dkg.Suite) ([]dkg.Justification, error) {
	ret := make([]dkg.Justification, 0)
	for _, j := range justifications {
		byts, err := hex.DecodeString(j.Share)
		if err != nil {
			return nil, err
		}

		point := suite.Scalar()
		if err := point.UnmarshalBinary(byts); err != nil {
			return nil, err
		}

		ret = append(ret, dkg.Justification{
			ShareIndex: j.ShareIndex,
			Share:      point,
		})
	}
	return ret, nil
}

type encodedJustificationBundle struct {
	DealerIndex    uint32
	Justifications []encodedJustification
	// SessionID of the current run
	SessionID []byte
	// Signature over the hash of the whole bundle
	Signature []byte
}

func EncodeJustificationBundle(bundle *dkg.JustificationBundle) ([]byte, error) {
	justifications, err := encodeJustifications(bundle.Justifications)
	if err != nil {
		return nil, err
	}
	toEncode := encodedJustificationBundle{
		DealerIndex:    bundle.DealerIndex,
		Justifications: justifications,
		SessionID:      bundle.SessionID,
		Signature:      bundle.Signature,
	}

	return json.MarshalIndent(toEncode, "", " ")
}

func DecodeJustificationBundle(byts []byte, suite dkg.Suite) (*dkg.JustificationBundle, error) {
	res := &encodedJustificationBundle{}
	if err := json.Unmarshal(byts, &res); err != nil {
		return nil, err
	}

	justifications, err := decodeJustifications(res.Justifications, suite)
	if err != nil {
		return nil, err
	}

	return &dkg.JustificationBundle{
		DealerIndex:    res.DealerIndex,
		Justifications: justifications,
		SessionID:      res.SessionID,
		Signature:      res.SessionID,
	}, nil
}
