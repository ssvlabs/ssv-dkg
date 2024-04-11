package wire

import (
	"encoding/hex"
	"encoding/json"
)

type reSignResultJSON struct {
	OperatorID     uint64 `json:"id"`
	RootPartialSig string `json:"root_partial_sig"`
}

func (p *ReSignResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(reSignResultJSON{
		OperatorID:     p.OperatorID,
		RootPartialSig: hex.EncodeToString(p.RootPartialSig),
	})
}
func (p *ReSignResult) UnmarshalJSON(data []byte) error {
	var r reSignResultJSON
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	var err error
	p.RootPartialSig, err = hex.DecodeString(r.RootPartialSig)
	if err != nil {
		return err
	}
	p.OperatorID = r.OperatorID
	return nil
}

type SignedVoluntaryExitJson struct {
	Exit      *VoluntaryExitJson `json:"message"`
	Signature string             `json:"signature" hex:"true"`
}
type VoluntaryExitJson struct {
	Epoch          string `json:"epoch"`
	ValidatorIndex string `json:"validator_index"`
}
