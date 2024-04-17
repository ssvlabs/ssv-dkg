package crypto

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/herumi/bls-eth-go-binary/bls"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	util "github.com/wealdtech/go-eth2-util"
)

const (
	// BLSWithdrawalPrefixByte is the BLS withdrawal prefix
	BLSWithdrawalPrefixByte = byte(0)
)

// withdrawalCredentialsHash forms a 32 byte hash of the withdrawal public
// address.
//
// The specification is as follows:
//
//	withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX_BYTE
//	withdrawal_credentials[1:] == hash(withdrawal_pubkey)[1:]
//
// where withdrawal_credentials is of type bytes32.
func BLSWithdrawalCredentials(withdrawalPubKey []byte) []byte {
	h := util.SHA256(withdrawalPubKey)
	return append([]byte{BLSWithdrawalPrefixByte}, h[1:]...)[:32]
}

func ParseWithdrawalCredentials(withdrawalCredentials []byte) (prefix byte, addr []byte) {
	return withdrawalCredentials[0], withdrawalCredentials[12:]
}

func SignDepositMessage(network e2m_core.Network, sk *bls.SecretKey, message *phase0.DepositMessage) (*phase0.DepositData, error) {
	signingRoot, err := spec_crypto.ComputeDepositMessageSigningRoot(network, message)
	if err != nil {
		return nil, err
	}

	// Sign.
	sig := sk.SignByte(signingRoot[:])
	if sig == nil {
		return nil, fmt.Errorf("failed to sign the root")
	}

	var phase0Sig phase0.BLSSignature
	copy(phase0Sig[:], sig.Serialize())

	return &phase0.DepositData{
		PublicKey:             message.PublicKey,
		Amount:                message.Amount,
		WithdrawalCredentials: message.WithdrawalCredentials,
		Signature:             phase0Sig,
	}, nil
}
