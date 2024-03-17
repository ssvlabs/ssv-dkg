package stubs

import (
	"context"
	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"math/big"
)

type Client struct {
	CallContractF func(call ethereum.CallMsg) ([]byte, error)
	CodeAtMap     map[common.Address]bool
}

func (c *Client) BlockNumber(ctx context.Context) (uint64, error) {
	return 100, nil
}

func (c *Client) CodeAt(ctx context.Context, contract common.Address, blockNumber *big.Int) ([]byte, error) {
	if c.CodeAtMap[contract] {
		return make([]byte, 1024), nil
	}
	return make([]byte, 0), nil
}

// CallContract executes an Ethereum contract call with the specified data as the
// input.
func (c *Client) CallContract(ctx context.Context, call ethereum.CallMsg, blockNumber *big.Int) ([]byte, error) {
	if c.CallContractF != nil {
		return c.CallContractF(call)
	}
	panic("implement")
}

func (c *Client) HeaderByNumber(ctx context.Context, number *big.Int) (*types.Header, error) {
	panic("implement")
}

// PendingCodeAt returns the code of the given account in the pending state.
func (c *Client) PendingCodeAt(ctx context.Context, account common.Address) ([]byte, error) {
	panic("implement")
}

// PendingNonceAt retrieves the current pending nonce associated with an account.
func (c *Client) PendingNonceAt(ctx context.Context, account common.Address) (uint64, error) {
	panic("implement")
}

// SuggestGasPrice retrieves the currently suggested gas price to allow a timely
// execution of a transaction.
func (c *Client) SuggestGasPrice(ctx context.Context) (*big.Int, error) {
	panic("implement")
}

// SuggestGasTipCap retrieves the currently suggested 1559 priority fee to allow
// a timely execution of a transaction.
func (c *Client) SuggestGasTipCap(ctx context.Context) (*big.Int, error) {
	panic("implement")
}

// EstimateGas tries to estimate the gas needed to execute a specific
// transaction based on the current pending state of the backend blockchain.
// There is no guarantee that this is the true gas limit requirement as other
// transactions may be added or removed by miners, but it should provide a basis
// for setting a reasonable default.
func (c *Client) EstimateGas(ctx context.Context, call ethereum.CallMsg) (gas uint64, err error) {
	panic("implement")
}

// SendTransaction injects the transaction into the pending pool for execution.
func (c *Client) SendTransaction(ctx context.Context, tx *types.Transaction) error {
	panic("implement")
}

// FilterLogs executes a log filter operation, blocking during execution and
// returning all the results in one batch.
//
// TODO(karalabe): Deprecate when the subscription one can return past data too.
func (c *Client) FilterLogs(ctx context.Context, query ethereum.FilterQuery) ([]types.Log, error) {
	panic("implement")
}

// SubscribeFilterLogs creates a background log filtering operation, returning
// a subscription immediately, which can be used to stream the found events.
func (c *Client) SubscribeFilterLogs(ctx context.Context, query ethereum.FilterQuery, ch chan<- types.Log) (ethereum.Subscription, error) {
	panic("implement")
}
