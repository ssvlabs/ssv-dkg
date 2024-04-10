package wire

import (
	"encoding/hex"
	"encoding/json"
)

type reSignResultJSON struct {
	OperatorID            uint64 `json:"id"`
	ExitMessagePartialSig string `json:"exit_partial_sig"`
}

func (p *ReSignResult) MarshalJSON() ([]byte, error) {
	return json.Marshal(reSignResultJSON{
		OperatorID:            p.OperatorID,
		ExitMessagePartialSig: hex.EncodeToString(p.ExitMessagePartialSig),
	})
}
func (p *ReSignResult) UnmarshalJSON(data []byte) error {
	var r reSignResultJSON
	if err := json.Unmarshal(data, &r); err != nil {
		return err
	}
	var err error
	p.ExitMessagePartialSig, err = hex.DecodeString(r.ExitMessagePartialSig)
	if err != nil {
		return err
	}
	p.OperatorID = r.OperatorID
	return nil
}
