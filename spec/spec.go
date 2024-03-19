package spec

import (
	"bytes"
	"context"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts/abi/bind"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv-dkg/spec/eip1271"
)

func RunDKG(init *wire.Init) ([]*wire.Result, error) {
	if err := ValidateInitMessage(init); err != nil {
		return nil, err
	}

	id := crypto.NewID()

	var results []*wire.Result
	/*
		DKG ceremony ...
	*/
	_, _, _, err := ValidateResults(
		init.Operators,
		init.WithdrawalCredentials,
		results[0].SignedProof.Proof.ValidatorPubKey,
		init.Fork,
		init.Owner,
		init.Nonce,
		id,
		results)
	return results, err
}

func RunReshare(
	validatorPK []byte,
	withdrawalCredentials []byte,
	fork [4]byte,
	signedReshare *wire.SignedReshare,
	proofs map[*wire.Operator]wire.SignedProof,
	client eip1271.ETHClient,
) ([]*wire.Result, error) {
	if err := VerifySignedReshare(client, signedReshare); err != nil {
		return nil, err
	}

	if err := ValidateReshareMessage(&signedReshare.Reshare, proofs); err != nil {
		return nil, err
	}

	id := crypto.NewID()

	var results []*wire.Result
	/*
		DKG ceremony ...
	*/
	_, _, _, err := ValidateResults(
		signedReshare.Reshare.NewOperators,
		withdrawalCredentials,
		validatorPK,
		fork,
		signedReshare.Reshare.Owner,
		signedReshare.Reshare.Nonce,
		id,
		results)
	return results, err
}

// VerifySignedReshare returns nil if signature over re-share message is valid
func VerifySignedReshare(client eip1271.ETHClient, signedReshare *wire.SignedReshare) error {
	isEOASignature, err := IsEOAAccount(client, signedReshare.Reshare.Owner)
	if err != nil {
		return err
	}

	hash, err := signedReshare.Reshare.HashTreeRoot()
	if err != nil {
		return err
	}

	if isEOASignature {
		pk, err := eth_crypto.SigToPub(hash[:], signedReshare.Signature)
		if err != nil {
			return err
		}

		address := eth_crypto.PubkeyToAddress(*pk)

		if common.Address(signedReshare.Reshare.Owner).Cmp(address) != 0 {
			return fmt.Errorf("invalid signed reshare signature")
		}
	} else {
		// EIP 1271 signature
		// gnosis implementation https://github.com/safe-global/safe-smart-account/blob/2278f7ccd502878feb5cec21dd6255b82df374b5/contracts/Safe.sol#L265
		// https://github.com/safe-global/safe-smart-account/blob/main/docs/signatures.md
		// ... verify via contract call
		signerVerification, err := eip1271.NewEip1271(signedReshare.Reshare.Owner, client)
		if err != nil {
			return err
		}
		res, err := signerVerification.IsValidSignature(&bind.CallOpts{
			Context: context.Background(),
		}, hash[:], signedReshare.Signature)
		if err != nil {
			return err
		}
		if !bytes.Equal(eip1271.MagicValue[:], res[:]) {
			return fmt.Errorf("signature invalid")
		}
	}

	return nil
}

func IsEOAAccount(client eip1271.ETHClient, address common.Address) (bool, error) {
	block, err := client.BlockNumber(context.Background())
	if err != nil {
		return false, err
	}

	code, err := client.CodeAt(context.Background(), address, (&big.Int{}).SetUint64(block))
	if err != nil {
		return false, err
	}
	return len(code) == 0, nil
}
