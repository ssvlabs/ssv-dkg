package crypto

import (
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	e2m_deposit "github.com/bloxapp/eth2-key-manager/eth1_deposit"
	"github.com/herumi/bls-eth-go-binary/bls"
	types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
)

const (
	// BLSWithdrawalPrefixByte is the BLS withdrawal prefix
	BLSWithdrawalPrefixByte  = byte(0)
	ETH1WithdrawalPrefixByte = byte(1)
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

func ETH1WithdrawalCredentials(withdrawalAddr []byte) []byte {
	withdrawalCredentials := make([]byte, 32)
	copy(withdrawalCredentials[:1], []byte{ETH1WithdrawalPrefixByte})
	// withdrawalCredentials[1:12] == b'\x00' * 11 // this is not needed since cells are zeroed anyway
	copy(withdrawalCredentials[12:], withdrawalAddr)
	return withdrawalCredentials
}

func ParseWithdrawalCredentials(withdrawalCredentials []byte) (prefix byte, addr []byte) {
	return withdrawalCredentials[0], withdrawalCredentials[12:]
}

func ComputeDepositMessageSigningRoot(network e2m_core.Network, message *phase0.DepositMessage) (phase0.Root, error) {
	if !e2m_deposit.IsSupportedDepositNetwork(network) {
		return phase0.Root{}, fmt.Errorf("network %s is not supported", network)
	}
	if len(message.WithdrawalCredentials) != 32 {
		return phase0.Root{}, fmt.Errorf("withdrawal credentials must be 32 bytes")
	}

	// Compute DepositMessage root.
	depositMsgRoot, err := message.HashTreeRoot()
	if err != nil {
		return phase0.Root{}, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return phase0.Root{}, fmt.Errorf("failed to calculate domain: %s", err)
	}
	container := &phase0.SigningData{
		ObjectRoot: depositMsgRoot,
		Domain:     phase0.Domain(domain),
	}
	signingRoot, err := container.HashTreeRoot()
	if err != nil {
		return phase0.Root{}, fmt.Errorf("failed to determine the root hash of signing container: %s", err)
	}
	return signingRoot, nil
}

func SignDepositMessage(network e2m_core.Network, sk *bls.SecretKey, message *phase0.DepositMessage) (*phase0.DepositData, error) {
	signingRoot, err := ComputeDepositMessageSigningRoot(network, message)
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

// VerifyDepositData reconstructs and checks BLS signatures for ETH2 deposit message
func VerifyDepositData(network e2m_core.Network, depositData *phase0.DepositData) error {
	signingRoot, err := ComputeDepositMessageSigningRoot(network, &phase0.DepositMessage{
		PublicKey:             depositData.PublicKey,
		Amount:                depositData.Amount,
		WithdrawalCredentials: depositData.WithdrawalCredentials,
	})
	if err != nil {
		return fmt.Errorf("failed to compute signing root: %s", err)
	}

	// Verify the signature.
	pkCopy := make([]byte, len(depositData.PublicKey))
	copy(pkCopy, depositData.PublicKey[:])
	pubkey, err := types.BLSPublicKeyFromBytes(pkCopy)
	if err != nil {
		return fmt.Errorf("failed to parse public key: %s", err)
	}

	sigCpy := make([]byte, len(depositData.Signature))
	copy(sigCpy, depositData.Signature[:])
	sig, err := types.BLSSignatureFromBytes(sigCpy)
	if err != nil {
		return fmt.Errorf("failed to parse signature: %s", err)
	}
	if !sig.Verify(signingRoot[:], pubkey) {
		return ErrInvalidSignature
	}
	return nil
}
