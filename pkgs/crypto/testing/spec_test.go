package testing

import (
	"testing"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/stretchr/testify/require"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto/eip1271"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto/testing/fixtures"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto/testing/stubs"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func TestVerifySignedReshare(t *testing.T) {
	t.Run("valid EOA signature", func(t *testing.T) {
		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				return nil, nil
			},
		}

		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		reshare := wire.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           address,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.NoError(t, crypto.VerifySignedReshare(stubClient, &wire.SignedReshare{
			Reshare:   reshare,
			Signature: sig,
		}))
	})

	t.Run("invalid EOA signature", func(t *testing.T) {
		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				return nil, nil
			},
		}

		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)

		reshare := wire.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           fixtures.TestOwnerAddress,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.EqualError(t, crypto.VerifySignedReshare(stubClient, &wire.SignedReshare{
			Reshare:   reshare,
			Signature: sig,
		}), "invalid signed reshare signature")
	})

	t.Run("valid contract signature", func(t *testing.T) {
		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.MagicValue[:])

				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{
				address: true,
			},
		}

		reshare := wire.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           address,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.NoError(t, crypto.VerifySignedReshare(stubClient, &wire.SignedReshare{
			Reshare:   reshare,
			Signature: sig,
		}))
	})

	t.Run("invalid contract signature", func(t *testing.T) {
		sk, err := eth_crypto.GenerateKey()
		require.NoError(t, err)
		address := eth_crypto.PubkeyToAddress(sk.PublicKey)

		stubClient := &stubs.Client{
			CallContractF: func(call ethereum.CallMsg) ([]byte, error) {
				ret := make([]byte, 32) // needs to be 32 byte for packing
				copy(ret[:4], eip1271.InvalidSigValue[:])

				return ret, nil
			},
			CodeAtMap: map[common.Address]bool{
				address: true,
			},
		}

		reshare := wire.Reshare{
			ValidatorPubKey: fixtures.ShareSK(fixtures.TestValidator4Operators).GetPublicKey().Serialize(),
			OldOperators:    fixtures.GenerateOperators(4),
			NewOperators:    fixtures.GenerateOperators(7),
			OldT:            3,
			NewT:            5,
			Owner:           address,
		}
		hash, err := reshare.HashTreeRoot()
		require.NoError(t, err)

		sig, err := eth_crypto.Sign(hash[:], sk)
		require.NoError(t, err)

		require.EqualError(t, crypto.VerifySignedReshare(stubClient, &wire.SignedReshare{
			Reshare:   reshare,
			Signature: sig,
		}), "signature invalid")
	})
}
