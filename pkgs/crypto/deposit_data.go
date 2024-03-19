package crypto

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"reflect"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/hashicorp/go-version"

	"github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func BuildDepositDataCLI(network core.Network, depositData *phase0.DepositData, depositCLIVersion string) (*wire.DepositDataCLI, error) {
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                MaxEffectiveBalanceInGwei,
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
	if !(MaxEffectiveBalanceInGwei == depositData.Amount) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong amount %d", depositData.Amount)
	}
	forkbytes := network.GenesisForkVersion()
	depositDataJson := &wire.DepositDataCLI{
		PubKey:                hex.EncodeToString(depositData.PublicKey[:]),
		WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
		Amount:                MaxEffectiveBalanceInGwei,
		Signature:             hex.EncodeToString(depositData.Signature[:]),
		DepositMessageRoot:    hex.EncodeToString(depositMsgRoot[:]),
		DepositDataRoot:       hex.EncodeToString(depositDataRoot[:]),
		ForkVersion:           hex.EncodeToString(forkbytes[:]),
		NetworkName:           string(network),
		DepositCliVersion:     depositCLIVersion,
	}
	return depositDataJson, nil
}

func ValidateDepositDataCLI(d *wire.DepositDataCLI, expectedWithdrawalAddress common.Address) error {
	return validateDepositDataCLI(d, ETH1WithdrawalCredentials(expectedWithdrawalAddress.Bytes()))
}

func ValidateDepositDataCLIBLS(d *wire.DepositDataCLI, expectedWithdrawalPubKey []byte) error {
	return validateDepositDataCLI(d, BLSWithdrawalCredentials(expectedWithdrawalPubKey))
}

func validateDepositDataCLI(d *wire.DepositDataCLI, expectedWithdrawalCredentials []byte) error {
	// Re-encode and re-decode the deposit data json to ensure encoding is valid.
	b, err := json.Marshal(d)
	if err != nil {
		return fmt.Errorf("failed to marshal deposit data json: %v", err)
	}
	var depositData wire.DepositDataCLI
	if err := json.Unmarshal(b, &depositData); err != nil {
		return fmt.Errorf("failed to unmarshal deposit data json: %v", err)
	}
	if !reflect.DeepEqual(d, &depositData) {
		return fmt.Errorf("failed to validate deposit data json")
	}
	d = &depositData

	// 1. Validate format
	if err := validateFieldFormatting(d); err != nil {
		return fmt.Errorf("failed to validate deposit data json: %v", err)
	}
	// 2. Verify deposit roots and signature
	if err := verifyDepositRoots(d); err != nil {
		return fmt.Errorf("failed to verify deposit roots: %v", err)
	}
	// 3. Verify withdrawal address
	if d.WithdrawalCredentials != hex.EncodeToString(expectedWithdrawalCredentials) {
		return fmt.Errorf("failed to verify withdrawal address (%s != %x)", d.WithdrawalCredentials, expectedWithdrawalCredentials)
	}
	return nil
}

func validateFieldFormatting(d *wire.DepositDataCLI) error {
	// check existence of required keys
	if d.PubKey == "" ||
		d.WithdrawalCredentials == "" ||
		d.Amount == 0 ||
		d.Signature == "" ||
		d.DepositMessageRoot == "" ||
		d.DepositDataRoot == "" ||
		d.ForkVersion == "" ||
		d.DepositCliVersion == "" {
		return fmt.Errorf("resulting deposit data json has wrong format")
	}
	// check type of values
	if reflect.TypeOf(d.PubKey).String() != "string" ||
		reflect.TypeOf(d.WithdrawalCredentials).String() != "string" ||
		reflect.TypeOf(d.Amount).String() != "phase0.Gwei" ||
		reflect.TypeOf(d.Signature).String() != "string" ||
		reflect.TypeOf(d.DepositMessageRoot).String() != "string" ||
		reflect.TypeOf(d.DepositDataRoot).String() != "string" ||
		reflect.TypeOf(d.ForkVersion).String() != "string" ||
		reflect.TypeOf(d.DepositCliVersion).String() != "string" {
		return fmt.Errorf("resulting deposit data json has wrong fields type")
	}
	// check length of strings (note: using string length, so 1 byte = 2 chars)
	if len(d.PubKey) != 96 ||
		len(d.WithdrawalCredentials) != 64 ||
		len(d.Signature) != 192 ||
		len(d.DepositMessageRoot) != 64 ||
		len(d.DepositDataRoot) != 64 ||
		len(d.ForkVersion) != 8 {
		return fmt.Errorf("resulting deposit data json has wrong fields length")
	}
	// check the deposit amount
	if d.Amount != 32000000000 {
		return fmt.Errorf("resulting deposit data json has wrong amount")
	}
	v, err := version.NewVersion(d.DepositCliVersion)
	if err != nil {
		return err
	}
	vMin, err := version.NewVersion("2.7.0")
	if err != nil {
		return err
	}
	// check the deposit-cli version
	if v.LessThan(vMin) {
		return fmt.Errorf("resulting deposit data json has wrong amount")
	}
	return nil
}

func verifyDepositRoots(d *wire.DepositDataCLI) error {
	pubKey, err := hex.DecodeString(d.PubKey)
	if err != nil {
		return fmt.Errorf("failed to decode public key: %v", err)
	}
	withdrCreds, err := hex.DecodeString(d.WithdrawalCredentials)
	if err != nil {
		return fmt.Errorf("failed to decode withdrawal credentials: %v", err)
	}
	sig, err := hex.DecodeString(d.Signature)
	if err != nil {
		return fmt.Errorf("failed to decode signature: %v", err)
	}
	fork, err := hex.DecodeString(d.ForkVersion)
	if err != nil {
		return fmt.Errorf("failed to decode fork version: %v", err)
	}
	if len(fork) != 4 {
		return fmt.Errorf("fork version has wrong length")
	}
	network, err := utils.GetNetworkByFork([4]byte(fork))
	if err != nil {
		return fmt.Errorf("failed to get network by fork: %v", err)
	}
	depositData := &phase0.DepositData{
		PublicKey:             phase0.BLSPubKey(pubKey),
		WithdrawalCredentials: withdrCreds,
		Amount:                d.Amount,
		Signature:             phase0.BLSSignature(sig),
	}
	err = VerifyDepositData(network, depositData)
	if err != nil {
		return fmt.Errorf("failed to verify deposit data: %v", err)
	}
	return nil
}
