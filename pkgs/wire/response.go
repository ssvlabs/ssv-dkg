package wire

import (
	"encoding/json"

	"github.com/drand/kyber/share/dkg"
)

func EncodeResponseBundle(bundle *dkg.ResponseBundle) ([]byte, error) {
	return json.MarshalIndent(bundle, "", " ")
}

func DecodeResponseBundle(byts []byte) (*dkg.ResponseBundle, error) {
	res := &dkg.ResponseBundle{}
	if err := json.Unmarshal(byts, &res); err != nil {
		return nil, err
	}
	return res, nil
}
