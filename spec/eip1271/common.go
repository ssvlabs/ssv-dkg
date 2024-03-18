package eip1271

import (
	"context"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
)

var MagicValue = [4]byte{16, 26, 0xba, 0x7e}
var InvalidSigValue = [4]byte{0xff, 0xff, 0xff, 0xff}

type ETHClient interface {
	BlockNumber(ctx context.Context) (uint64, error)
	bind.ContractBackend
}
