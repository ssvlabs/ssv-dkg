package validator

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/ethereum/go-ethereum/common"
)

type ResultsDir struct {
	AggregatedDepositData []*wire.DepositDataCLI
	AggregatedKeyShares   *wire.KeySharesCLI
	AggregatedProofs      [][]*wire.SignedProof
	Validators            []ResultsValidatorDir
}

type ResultsValidatorDir struct {
	DepositData []*wire.DepositDataCLI
	KeyShares   *wire.KeySharesCLI
	Proofs      []*wire.SignedProof
}

func ValidateResultsDir(dir string, validatorCount int, ownerAddress common.Address, ownerNonce uint64, withdrawAddress common.Address) error {
	var results ResultsDir

	// Load aggregated data.
	aggregations := validatorCount > 1
	if aggregations {
		if err := loadJSONFile(filepath.Join(dir, "deposit_data.json"), &results.AggregatedDepositData); err != nil {
			return err
		}
		if err := loadJSONFile(filepath.Join(dir, "keyshares.json"), &results.AggregatedKeyShares); err != nil {
			return err
		}
		if err := loadJSONFile(filepath.Join(dir, "proofs.json"), &results.AggregatedProofs); err != nil {
			return err
		}
	}

	// Load validator data.
	currentNonce := ownerNonce
	for i := 0; i < validatorCount; i++ {
		matches, err := filepath.Glob(filepath.Join(dir, fmt.Sprintf("%06d-0x%s", currentNonce, "*")))
		if err != nil {
			return fmt.Errorf("failed to match validator directory: %w", err)
		}
		if len(matches) == 0 {
			return fmt.Errorf("validator directory not found")
		}
		if len(matches) > 1 {
			return fmt.Errorf("multiple validator directories found for nonce %d", currentNonce)
		}

		var validator ResultsValidatorDir
		validatorDir := matches[0]
		if err := loadJSONFile(filepath.Join(validatorDir, "deposit_data.json"), &validator.DepositData); err != nil {
			return err
		}
		if err := loadJSONFile(filepath.Join(validatorDir, "keyshares.json"), &validator.KeyShares); err != nil {
			return err
		}
		if err := loadJSONFile(filepath.Join(validatorDir, "proofs.json"), &validator.Proofs); err != nil {
			return err
		}
		if len(validator.DepositData) != 1 {
			return fmt.Errorf("validator deposit-data contains more than one item")
		}
		if len(validator.KeyShares.Shares) != 1 {
			return fmt.Errorf("validator keyshares contains more than one item")
		}
		if len(validator.Proofs) == 0 {
			return fmt.Errorf("validator proofs is empty")
		}

		// Verify that the validator data is equal to the aggregated data.
		if aggregations {
			depositData := results.AggregatedDepositData[i]
			proofs := results.AggregatedProofs[i]
			if !reflect.DeepEqual([]*wire.DepositDataCLI{depositData}, validator.DepositData) {
				return fmt.Errorf("validator deposit data does not match aggregated deposit data")
			}
			if !reflect.DeepEqual(results.AggregatedKeyShares.Shares[i], validator.KeyShares.Shares[0]) {
				return fmt.Errorf("validator key shares does not match aggregated key shares")
			}
			if !reflect.DeepEqual(proofs, validator.Proofs) {
				return fmt.Errorf("validator proofs does not match aggregated proofs")
			}
		}

		results.Validators = append(results.Validators, validator)
		currentNonce++
	}

	// Check that there are no other directories (ignoring the aggregated data).
	entries, err := os.ReadDir(dir)
	if err != nil {
		return fmt.Errorf("failed to read directory: %w", err)
	}
	dirs := 0
	for _, entry := range entries {
		if !entry.IsDir() {
			if entry.Name() == "deposit_data.json" || entry.Name() == "keyshares.json" || entry.Name() == "proofs.json" {
				continue
			}
			return fmt.Errorf("unexpected file in directory: %s", entry.Name())
		}
		dirs++
	}
	if dirs != validatorCount {
		return fmt.Errorf("unexpected number of directories: %d", dirs)
	}

	aggregatedDepositData := results.AggregatedDepositData
	aggregatedKeyShares := results.AggregatedKeyShares
	aggregatedProofs := results.AggregatedProofs
	if !aggregations {
		// There are no aggregation files, so we need to aggregate the data ourselves for validation.
		aggregatedKeyShares = &wire.KeySharesCLI{
			CreatedAt: results.Validators[0].KeyShares.CreatedAt,
			Version:   results.Validators[0].KeyShares.Version,
		}
		for _, validator := range results.Validators {
			aggregatedDepositData = append(aggregatedDepositData, validator.DepositData[0])
			aggregatedKeyShares.Shares = append(aggregatedKeyShares.Shares, validator.KeyShares.Shares[0])
			aggregatedProofs = append(aggregatedProofs, validator.Proofs)
		}
	}
	return ValidateResults(aggregatedDepositData, aggregatedKeyShares, aggregatedProofs, validatorCount, ownerAddress, ownerNonce, withdrawAddress)
}

func OpenResultsDir(dir string) (*ResultsDir, error) {
	var results ResultsDir
	if err := loadJSONFile(filepath.Join(dir, "deposit_data.json"), &results.AggregatedDepositData); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load deposit data: %w", err)
	}
	if err := loadJSONFile(filepath.Join(dir, "keyshares.json"), &results.AggregatedKeyShares); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load keyshares: %w", err)
	}
	if err := loadJSONFile(filepath.Join(dir, "proofs.json"), &results.AggregatedProofs); err != nil && !os.IsNotExist(err) {
		return nil, fmt.Errorf("failed to load proofs: %w", err)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		var validator ResultsValidatorDir
		validatorDir := filepath.Join(dir, entry.Name())
		if err := loadJSONFile(filepath.Join(validatorDir, "deposit_data.json"), &validator.DepositData); err != nil {
			return nil, fmt.Errorf("failed to load validator deposit data: %w", err)
		}
		if err := loadJSONFile(filepath.Join(validatorDir, "keyshares.json"), &validator.KeyShares); err != nil {
			return nil, fmt.Errorf("failed to load validator keyshares: %w", err)
		}
		if err := loadJSONFile(filepath.Join(validatorDir, "proofs.json"), &validator.Proofs); err != nil {
			return nil, fmt.Errorf("failed to load validator proofs: %w", err)
		}
		results.Validators = append(results.Validators, validator)
	}
	return &results, nil
}

func loadJSONFile(file string, v interface{}) error {
	data, err := os.ReadFile(file)
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}
