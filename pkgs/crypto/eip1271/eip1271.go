// Code generated - DO NOT EDIT.
// This file is a generated binding and any manual changes will be lost.

package eip1271

import (
	"errors"
	"math/big"
	"strings"

	ethereum "github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/event"
)

// Reference imports to suppress errors if they are not otherwise used.
var (
	_ = errors.New
	_ = big.NewInt
	_ = strings.NewReader
	_ = ethereum.NotFound
	_ = bind.Bind
	_ = common.Big1
	_ = types.BloomLookup
	_ = event.NewSubscription
	_ = abi.ConvertType
)

// Eip1271MetaData contains all meta data concerning the Eip1271 contract.
var Eip1271MetaData = &bind.MetaData{
	ABI: "[{\"constant\":true,\"inputs\":[{\"name\":\"_data\",\"type\":\"bytes\"},{\"name\":\"_signature\",\"type\":\"bytes\"}],\"name\":\"isValidSignature\",\"outputs\":[{\"name\":\"magicValue\",\"type\":\"bytes4\"}],\"payable\":false,\"stateMutability\":\"view\",\"type\":\"function\"}]",
}

// Eip1271ABI is the input ABI used to generate the binding from.
// Deprecated: Use Eip1271MetaData.ABI instead.
var Eip1271ABI = Eip1271MetaData.ABI

// Eip1271 is an auto generated Go binding around an Ethereum contract.
type Eip1271 struct {
	Eip1271Caller     // Read-only binding to the contract
	Eip1271Transactor // Write-only binding to the contract
	Eip1271Filterer   // Log filterer for contract events
}

// Eip1271Caller is an auto generated read-only Go binding around an Ethereum contract.
type Eip1271Caller struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Eip1271Transactor is an auto generated write-only Go binding around an Ethereum contract.
type Eip1271Transactor struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Eip1271Filterer is an auto generated log filtering Go binding around an Ethereum contract events.
type Eip1271Filterer struct {
	contract *bind.BoundContract // Generic contract wrapper for the low level calls
}

// Eip1271Session is an auto generated Go binding around an Ethereum contract,
// with pre-set call and transact options.
type Eip1271Session struct {
	Contract     *Eip1271          // Generic contract binding to set the session for
	CallOpts     bind.CallOpts     // Call options to use throughout this session
	TransactOpts bind.TransactOpts // Transaction auth options to use throughout this session
}

// Eip1271CallerSession is an auto generated read-only Go binding around an Ethereum contract,
// with pre-set call options.
type Eip1271CallerSession struct {
	Contract *Eip1271Caller // Generic contract caller binding to set the session for
	CallOpts bind.CallOpts  // Call options to use throughout this session
}

// Eip1271TransactorSession is an auto generated write-only Go binding around an Ethereum contract,
// with pre-set transact options.
type Eip1271TransactorSession struct {
	Contract     *Eip1271Transactor // Generic contract transactor binding to set the session for
	TransactOpts bind.TransactOpts  // Transaction auth options to use throughout this session
}

// Eip1271Raw is an auto generated low-level Go binding around an Ethereum contract.
type Eip1271Raw struct {
	Contract *Eip1271 // Generic contract binding to access the raw methods on
}

// Eip1271CallerRaw is an auto generated low-level read-only Go binding around an Ethereum contract.
type Eip1271CallerRaw struct {
	Contract *Eip1271Caller // Generic read-only contract binding to access the raw methods on
}

// Eip1271TransactorRaw is an auto generated low-level write-only Go binding around an Ethereum contract.
type Eip1271TransactorRaw struct {
	Contract *Eip1271Transactor // Generic write-only contract binding to access the raw methods on
}

// NewEip1271 creates a new instance of Eip1271, bound to a specific deployed contract.
func NewEip1271(address common.Address, backend bind.ContractBackend) (*Eip1271, error) {
	contract, err := bindEip1271(address, backend, backend, backend)
	if err != nil {
		return nil, err
	}
	return &Eip1271{Eip1271Caller: Eip1271Caller{contract: contract}, Eip1271Transactor: Eip1271Transactor{contract: contract}, Eip1271Filterer: Eip1271Filterer{contract: contract}}, nil
}

// NewEip1271Caller creates a new read-only instance of Eip1271, bound to a specific deployed contract.
func NewEip1271Caller(address common.Address, caller bind.ContractCaller) (*Eip1271Caller, error) {
	contract, err := bindEip1271(address, caller, nil, nil)
	if err != nil {
		return nil, err
	}
	return &Eip1271Caller{contract: contract}, nil
}

// NewEip1271Transactor creates a new write-only instance of Eip1271, bound to a specific deployed contract.
func NewEip1271Transactor(address common.Address, transactor bind.ContractTransactor) (*Eip1271Transactor, error) {
	contract, err := bindEip1271(address, nil, transactor, nil)
	if err != nil {
		return nil, err
	}
	return &Eip1271Transactor{contract: contract}, nil
}

// NewEip1271Filterer creates a new log filterer instance of Eip1271, bound to a specific deployed contract.
func NewEip1271Filterer(address common.Address, filterer bind.ContractFilterer) (*Eip1271Filterer, error) {
	contract, err := bindEip1271(address, nil, nil, filterer)
	if err != nil {
		return nil, err
	}
	return &Eip1271Filterer{contract: contract}, nil
}

// bindEip1271 binds a generic wrapper to an already deployed contract.
func bindEip1271(address common.Address, caller bind.ContractCaller, transactor bind.ContractTransactor, filterer bind.ContractFilterer) (*bind.BoundContract, error) {
	parsed, err := Eip1271MetaData.GetAbi()
	if err != nil {
		return nil, err
	}
	return bind.NewBoundContract(address, *parsed, caller, transactor, filterer), nil
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Eip1271 *Eip1271Raw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Eip1271.Contract.Eip1271Caller.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Eip1271 *Eip1271Raw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Eip1271.Contract.Eip1271Transactor.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Eip1271 *Eip1271Raw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Eip1271.Contract.Eip1271Transactor.contract.Transact(opts, method, params...)
}

// Call invokes the (constant) contract method with params as input values and
// sets the output to result. The result type might be a single field for simple
// returns, a slice of interfaces for anonymous returns and a struct for named
// returns.
func (_Eip1271 *Eip1271CallerRaw) Call(opts *bind.CallOpts, result *[]interface{}, method string, params ...interface{}) error {
	return _Eip1271.Contract.contract.Call(opts, result, method, params...)
}

// Transfer initiates a plain transaction to move funds to the contract, calling
// its default method if one is available.
func (_Eip1271 *Eip1271TransactorRaw) Transfer(opts *bind.TransactOpts) (*types.Transaction, error) {
	return _Eip1271.Contract.contract.Transfer(opts)
}

// Transact invokes the (paid) contract method with params as input values.
func (_Eip1271 *Eip1271TransactorRaw) Transact(opts *bind.TransactOpts, method string, params ...interface{}) (*types.Transaction, error) {
	return _Eip1271.Contract.contract.Transact(opts, method, params...)
}

// IsValidSignature is a free data retrieval call binding the contract method 0x20c13b0b.
//
// Solidity: function isValidSignature(bytes _data, bytes _signature) view returns(bytes4 magicValue)
func (_Eip1271 *Eip1271Caller) IsValidSignature(opts *bind.CallOpts, _data []byte, _signature []byte) ([4]byte, error) {
	var out []interface{}
	err := _Eip1271.contract.Call(opts, &out, "isValidSignature", _data, _signature)

	if err != nil {
		return *new([4]byte), err
	}

	out0 := *abi.ConvertType(out[0], new([4]byte)).(*[4]byte)

	return out0, err

}

// IsValidSignature is a free data retrieval call binding the contract method 0x20c13b0b.
//
// Solidity: function isValidSignature(bytes _data, bytes _signature) view returns(bytes4 magicValue)
func (_Eip1271 *Eip1271Session) IsValidSignature(_data []byte, _signature []byte) ([4]byte, error) {
	return _Eip1271.Contract.IsValidSignature(&_Eip1271.CallOpts, _data, _signature)
}

// IsValidSignature is a free data retrieval call binding the contract method 0x20c13b0b.
//
// Solidity: function isValidSignature(bytes _data, bytes _signature) view returns(bytes4 magicValue)
func (_Eip1271 *Eip1271CallerSession) IsValidSignature(_data []byte, _signature []byte) ([4]byte, error) {
	return _Eip1271.Contract.IsValidSignature(&_Eip1271.CallOpts, _data, _signature)
}
