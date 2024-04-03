package validator

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"strconv"
	"strings"

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
	Nonce       uint64
	PublicKey   string
	DepositData []*wire.DepositDataCLI
	KeyShares   *wire.KeySharesCLI
	Proofs      []*wire.SignedProof
}

func ValidateResultsDir(dir string, validatorCount int, ownerAddress common.Address, ownerNonce uint64, withdrawAddress common.Address) error {
	if validatorCount < 1 {
		return fmt.Errorf("validator count is less than 1")
	}

	results, err := OpenResultsDir(dir)
	if err != nil {
		return fmt.Errorf("failed to open results directory: %w", err)
	}
	if len(results.Validators) != validatorCount {
		return fmt.Errorf("unexpected number of validators: %d", len(results.Validators))
	}
	if validatorCount > 1 &&
		(len(results.AggregatedDepositData) != validatorCount ||
			len(results.AggregatedKeyShares.Shares) != validatorCount ||
			len(results.AggregatedProofs) != validatorCount) {
		return fmt.Errorf("inconsistent number of entries in aggregated deposit-data, keyshares and proofs")
	}

	// Load validator data.
	currentNonce := ownerNonce
	for i, validator := range results.Validators {
		if validator.Nonce != currentNonce {
			return fmt.Errorf("unexpected nonce: %d", validator.Nonce)
		}
		if len(validator.DepositData) != 1 {
			return fmt.Errorf("validator deposit-data contains more than one item")
		}
		if len(validator.KeyShares.Shares) != 1 {
			return fmt.Errorf("validator keyshares contains more than one item")
		}
		if len(validator.Proofs) != len(validator.KeyShares.Shares[0].Payload.OperatorIDs) {
			return fmt.Errorf("number of validator proofs does not match operator count %d %d", len(validator.Proofs), len(validator.KeyShares.Shares[0].Payload.OperatorIDs))
		}

		// Check that the public key matches the one in deposit-data, keyshares and proofs.
		if validator.DepositData[0].PubKey != validator.PublicKey {
			return fmt.Errorf("validator public key does not match deposit-data public key")
		}
		if validator.KeyShares.Shares[0].Payload.PublicKey != "0x"+validator.PublicKey {
			return fmt.Errorf("validator public key does not match keyshares public key")
		}
		for _, proof := range validator.Proofs {
			if hex.EncodeToString(proof.Proof.ValidatorPubKey) != validator.PublicKey {
				return fmt.Errorf("validator public key does not match proof public key")
			}
		}

		// Verify that the validator data is equal to the aggregated data.
		if validatorCount > 1 {
			depositData := results.AggregatedDepositData[i]
			keyshares := results.AggregatedKeyShares.Shares[i]
			proofs := results.AggregatedProofs[i]

			if !reflect.DeepEqual([]*wire.DepositDataCLI{depositData}, validator.DepositData) {
				return fmt.Errorf("validator deposit data does not match aggregated deposit data")
			}
			if !reflect.DeepEqual(keyshares, validator.KeyShares.Shares[0]) {
				return fmt.Errorf("validator key shares does not match aggregated key shares")
			}
			if !reflect.DeepEqual(proofs, validator.Proofs) {
				return fmt.Errorf("validator proofs does not match aggregated proofs")
			}

			if err := jsonEqual([]*wire.DepositDataCLI{depositData}, validator.DepositData); err != nil {
				return fmt.Errorf("validator deposit data does not match aggregated deposit data: %w", err)
			}
			if err := jsonEqual(keyshares, validator.KeyShares.Shares[0]); err != nil {
				return fmt.Errorf("validator key shares does not match aggregated key shares: %w", err)
			}
			if err := jsonEqual(proofs, validator.Proofs); err != nil {
				return fmt.Errorf("validator proofs does not match aggregated proofs: %w", err)
			}
		}

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
			if isSystemFile(entry.Name()) {
				continue
			}
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
	if validatorCount == 1 {
		// There are no aggregation files, so we need to aggregate the data ourselves for validation.
		aggregatedKeyShares = &wire.KeySharesCLI{
			CreatedAt: results.Validators[0].KeyShares.CreatedAt,
			Version:   results.Validators[0].KeyShares.Version,
		}
		validator := results.Validators[0]
		aggregatedDepositData = append(aggregatedDepositData, validator.DepositData[0])
		aggregatedKeyShares.Shares = append(aggregatedKeyShares.Shares, validator.KeyShares.Shares[0])
		aggregatedProofs = append(aggregatedProofs, validator.Proofs)
	}
	return ValidateResults(aggregatedDepositData, aggregatedKeyShares, aggregatedProofs, validatorCount, ownerAddress, ownerNonce, withdrawAddress)
}

var regexpValidatorDir = regexp.MustCompile(`^(\d+)-0x([0-9a-f]{96})$`)

// OpenResultsDir loads the given directory into an unvalidated ResultsDir.
func OpenResultsDir(dir string) (*ResultsDir, error) {
	var results ResultsDir
	files, err := os.ReadDir(dir)
	if err != nil {
		return nil, fmt.Errorf("failed to read directory: %w", err)
	}
	foundAggregations := false
	for _, file := range files {
		if !file.IsDir() {
			if isSystemFile(file.Name()) {
				continue
			}
			if file.Name() == "deposit_data.json" || file.Name() == "keyshares.json" || file.Name() == "proofs.json" {
				foundAggregations = true
				continue
			}
			return nil, fmt.Errorf("unexpected file in directory: %s", file.Name())
		}

		matches := regexpValidatorDir.FindStringSubmatch(file.Name())
		if matches == nil {
			return nil, fmt.Errorf("unexpected file: %s", file.Name())
		}
		nonce, err := strconv.ParseUint(matches[1], 10, 64)
		if err != nil {
			return nil, fmt.Errorf("failed to parse nonce: %w", err)
		}
		validator := ResultsValidatorDir{
			Nonce:     nonce,
			PublicKey: matches[2],
		}

		validatorDir := filepath.Join(dir, file.Name())
		if err := loadJSONFile(filepath.Join(validatorDir, "deposit_data.json"), &validator.DepositData); err != nil {
			return nil, fmt.Errorf("failed to load deposit data: %w", err)
		}
		if err := loadJSONFile(filepath.Join(validatorDir, "keyshares.json"), &validator.KeyShares); err != nil {
			return nil, fmt.Errorf("failed to load keyshares: %w", err)
		}
		if err := loadJSONFile(filepath.Join(validatorDir, "proofs.json"), &validator.Proofs); err != nil {
			return nil, fmt.Errorf("failed to load proofs: %w", err)
		}

		results.Validators = append(results.Validators, validator)
	}
	if len(results.Validators) == 0 {
		return nil, fmt.Errorf("no validator directories found")
	}
	if len(results.Validators) > 1 {
		if err := loadJSONFile(filepath.Join(dir, "deposit_data.json"), &results.AggregatedDepositData); err != nil {
			return nil, fmt.Errorf("failed to load aggregated deposit data: %w", err)
		}
		if err := loadJSONFile(filepath.Join(dir, "keyshares.json"), &results.AggregatedKeyShares); err != nil {
			return nil, fmt.Errorf("failed to load aggregated keyshares: %w", err)
		}
		if err := loadJSONFile(filepath.Join(dir, "proofs.json"), &results.AggregatedProofs); err != nil {
			return nil, fmt.Errorf("failed to load aggregated proofs: %w", err)
		}
	} else if foundAggregations {
		return nil, fmt.Errorf("aggregation files found for single validator")
	}
	return &results, nil
}

func loadJSONFile(file string, v interface{}) error {
	data, err := os.ReadFile(filepath.Clean(file))
	if err != nil {
		return err
	}
	return json.Unmarshal(data, v)
}

func jsonEqual(a, b any) error {
	ja, err := json.Marshal(a)
	if err != nil {
		return fmt.Errorf("failed to marshal a: %w", err)
	}
	jb, err := json.Marshal(b)
	if err != nil {
		return fmt.Errorf("failed to marshal b: %w", err)
	}
	if string(ja) != string(jb) {
		return fmt.Errorf("json does not match: %s != %s", ja, jb)
	}
	return nil
}

// isSystemFile determines if the filename corresponds to a system file
// that should be ignored.
func isSystemFile(filename string) bool {
	// List of system files to ignore
	ignoreFiles := []string{".DS_Store", "Thumbs.db"}

	for _, ignore := range ignoreFiles {
		if strings.HasSuffix(filename, ignore) {
			return true
		}
	}
	return false
}
