package wire

import (
	"crypto/rand"
	"math/big"
)

func GetRandRequestID() [24]byte {
	requestID := [24]byte{}
	for i := range requestID {
		rndInt, _ := rand.Int(rand.Reader, big.NewInt(255))
		if len(rndInt.Bytes()) == 0 {
			requestID[i] = 0
		} else {
			requestID[i] = rndInt.Bytes()[0]
		}
	}
	return requestID
}
