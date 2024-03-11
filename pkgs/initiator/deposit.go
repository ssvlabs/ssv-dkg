package initiator

import (
	"encoding/hex"
	"fmt"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
)

// DepositDataCLI  is a deposit structure from the eth2 deposit CLI (https://github.com/ethereum/staking-deposit-cli).
type DepositDataCLI struct {
	PubKey                string      `json:"pubkey"`
	WithdrawalCredentials string      `json:"withdrawal_credentials"`
	Amount                phase0.Gwei `json:"amount"`
	Signature             string      `json:"signature"`
	DepositMessageRoot    string      `json:"deposit_message_root"`
	DepositDataRoot       string      `json:"deposit_data_root"`
	ForkVersion           string      `json:"fork_version"`
	NetworkName           string      `json:"network_name"`
	DepositCliVersion     string      `json:"deposit_cli_version"`
}

// DepositCliVersion is last version accepted by launchpad
const DepositCliVersion = "2.7.0"

func BuildDepositDataCLI(network core.Network, depositData *phase0.DepositData, depositCLIVersion string) (*DepositDataCLI, error) {
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                dkg.MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, err := depositMsg.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit message root: %v", err)
	}

	depositDataRoot, err := depositData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit data root: %v", err)
	}

	// Final checks of prepared deposit data
	if !(dkg.MaxEffectiveBalanceInGwei == depositData.Amount) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong amount %d", depositData.Amount)
	}
	forkbytes := network.GenesisForkVersion()
	depositDataJson := &DepositDataCLI{
		PubKey:                hex.EncodeToString(depositData.PublicKey[:]),
		WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
		Amount:                dkg.MaxEffectiveBalanceInGwei,
		Signature:             hex.EncodeToString(depositData.Signature[:]),
		DepositMessageRoot:    hex.EncodeToString(depositMsgRoot[:]),
		DepositDataRoot:       hex.EncodeToString(depositDataRoot[:]),
		ForkVersion:           hex.EncodeToString(forkbytes[:]),
		NetworkName:           string(network),
		DepositCliVersion:     depositCLIVersion,
	}
	return depositDataJson, nil
}
