package utils

import (
	"crypto/rand"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/bloxapp/ssv/logging"
	"github.com/ethereum/go-ethereum/common"
	"github.com/spf13/cobra"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/initiator"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/validator"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// StringSliceToUintArray converts the string slice to uint64 slice
func StringSliceToUintArray(flagdata []string) ([]uint64, error) {
	partsarr := make([]uint64, 0, len(flagdata))
	for i := 0; i < len(flagdata); i++ {
		opid, err := strconv.ParseUint(flagdata[i], 10, strconv.IntSize)
		if err != nil {
			return nil, fmt.Errorf("😥 cant load operator err: %v , data: %v, ", err, flagdata[i])
		}
		partsarr = append(partsarr, opid)
	}
	// sort array
	sort.SliceStable(partsarr, func(i, j int) bool {
		return partsarr[i] < partsarr[j]
	})
	sorted := sort.SliceIsSorted(partsarr, func(p, q int) bool {
		return partsarr[p] < partsarr[q]
	})
	if !sorted {
		return nil, fmt.Errorf("slice isnt sorted")
	}
	return partsarr, nil
}

func SignaturesStringToBytes(signatures string) ([]byte, error) {
	sig, err := hex.DecodeString(signatures)
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to parse signatures: %s", err)
	}
	return sig, nil
}

func DecodeProofsString(proofsString string) ([][]*spec.SignedProof, error) {
	allProofs := make([][]*wire.SignedProof, 0)
	err := json.Unmarshal([]byte(proofsString), &allProofs)
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to unmarshal proofs: %s", err)
	}
	allSpecProofs := make([][]*spec.SignedProof, len(allProofs))
	for i, sp := range allProofs {
		specProofs := make([]*spec.SignedProof, len(sp))
		for j, p := range sp {
			specProofs[j] = &p.SignedProof
		}
		allSpecProofs[i] = specProofs
	}
	return allSpecProofs, nil
}

func WriteResults(
	logger *zap.Logger,
	depositDataArr []*wire.DepositDataCLI,
	keySharesArr []*wire.KeySharesCLI,
	proofs [][]*wire.SignedProof,
	withRandomness bool,
	expectedValidatorCount int,
	expectedOwnerAddress common.Address,
	expectedOwnerNonce uint64,
	expectedWithdrawAddress common.Address,
	outputPath string,
) (err error) {
	if expectedValidatorCount == 0 {
		return fmt.Errorf("expectedValidatorCount is 0")
	}
	if len(depositDataArr) != len(keySharesArr) || len(depositDataArr) != len(proofs) {
		return fmt.Errorf("Incoming result arrays have inconsistent length")
	}
	if len(depositDataArr) == 0 {
		return fmt.Errorf("no results to write")
	}
	if len(depositDataArr) != int(expectedValidatorCount) {
		return fmt.Errorf("expectedValidatorCount is not equal to the length of given results")
	}

	// order the keyshares by nonce
	sort.SliceStable(keySharesArr, func(i, j int) bool {
		return keySharesArr[i].Shares[0].ShareData.OwnerNonce < keySharesArr[j].Shares[0].ShareData.OwnerNonce
	})
	sorted := sort.SliceIsSorted(keySharesArr, func(p, q int) bool {
		return keySharesArr[p].Shares[0].ShareData.OwnerNonce < keySharesArr[q].Shares[0].ShareData.OwnerNonce
	})
	if !sorted {
		return fmt.Errorf("slice is not sorted")
	}

	// check if public keys are unique
	for i := 0; i < len(keySharesArr)-1; i++ {
		pk1 := keySharesArr[i].Shares[0].Payload.PublicKey
		pk2 := keySharesArr[i+1].Shares[0].Payload.PublicKey
		if pk1 == pk2 {
			return fmt.Errorf("public key %s is not unique", keySharesArr[i].Shares[0].Payload.PublicKey)
		}
	}

	// order deposit data and proofs to match keyshares order
	sortedDepositData := make([]*wire.DepositDataCLI, len(depositDataArr))
	sortedProofs := make([][]*wire.SignedProof, len(depositDataArr))
	for i, keyshare := range keySharesArr {
		pk := strings.TrimPrefix(keyshare.Shares[0].Payload.PublicKey, "0x")
		for _, deposit := range depositDataArr {
			if deposit.PubKey == pk {
				sortedDepositData[i] = deposit
				break
			}
		}
		if sortedDepositData[i] == nil {
			return fmt.Errorf("failed to match deposit data with keyshares")
		}
		for _, proof := range proofs {
			if hex.EncodeToString(proof[0].Proof.ValidatorPubKey) == pk {
				sortedProofs[i] = proof
				break
			}
		}
		if sortedProofs[i] == nil {
			return fmt.Errorf("failed to match proofs with keyshares")
		}
	}
	depositDataArr = sortedDepositData
	proofs = sortedProofs

	// Validate the results.
	aggregatedKeyshares := &wire.KeySharesCLI{
		Version:   keySharesArr[0].Version,
		CreatedAt: keySharesArr[0].CreatedAt,
	}
	for i := 0; i < len(keySharesArr); i++ {
		aggregatedKeyshares.Shares = append(aggregatedKeyshares.Shares, keySharesArr[i].Shares...)
	}
	if err := validator.ValidateResults(depositDataArr, aggregatedKeyshares, proofs, expectedValidatorCount, expectedOwnerAddress, expectedOwnerNonce, expectedWithdrawAddress); err != nil {
		return err
	}

	// Create the ceremony directory.
	timestamp := time.Now().UTC().Format("2006-01-02--15-04-05.000")
	dirName := fmt.Sprintf("ceremony-%s", timestamp)
	if withRandomness {
		randomness := make([]byte, 4)
		if _, err := rand.Read(randomness); err != nil {
			return fmt.Errorf("failed to generate randomness: %w", err)
		}
		dirName = fmt.Sprintf("%s--%x", dirName, randomness)
	}
	dir := filepath.Join(outputPath, dirName)
	err = os.Mkdir(dir, os.ModePerm)
	if os.IsExist(err) {
		return fmt.Errorf("ceremony directory already exists: %w", err)
	}
	if err != nil {
		return fmt.Errorf("failed to create a ceremony directory: %w", err)
	}

	// If saving fails, create a "FAILED" file under the ceremony directory.
	defer func() {
		if err != nil {
			if err := os.WriteFile(filepath.Join(dir, "FAILED"), []byte(err.Error()), 0o600); err != nil {
				logger.Error("failed to write error file", zap.Error(err))
			}
		}
	}()

	for i := 0; i < len(depositDataArr); i++ {
		nestedDir := fmt.Sprintf("%s/%06d-0x%s", dir, keySharesArr[i].Shares[0].ShareData.OwnerNonce, depositDataArr[i].PubKey)
		err := os.Mkdir(nestedDir, os.ModePerm)
		if err != nil {
			return fmt.Errorf("failed to create a validator key directory: %w", err)
		}
		logger.Info("💾 Writing deposit data json", zap.String("path", nestedDir))
		err = WriteDepositResult(depositDataArr[i], nestedDir)
		if err != nil {
			logger.Error("Failed writing deposit data file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("deposit", depositDataArr[i]))
			return fmt.Errorf("failed writing deposit data file: %w", err)
		}
		logger.Info("💾 Writing keyshares payload to file", zap.String("path", nestedDir))
		err = WriteKeysharesResult(keySharesArr[i], nestedDir)
		if err != nil {
			logger.Error("Failed writing keyshares file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("deposit", keySharesArr[i]))
			return fmt.Errorf("failed writing keyshares file: %w", err)
		}
		logger.Info("💾 Writing proofs to file", zap.String("path", nestedDir))
		err = WriteProofs(proofs[i], nestedDir)
		if err != nil {
			logger.Error("Failed writing proofs file: ", zap.Error(err), zap.String("path", nestedDir), zap.Any("proof", proofs[i]))
			return fmt.Errorf("failed writing proofs file: %w", err)
		}
	}
	// if there is only one Validator, do not create summary files
	if expectedValidatorCount > 1 {
		err := WriteAggregatedInitResults(dir, depositDataArr, keySharesArr, proofs, logger)
		if err != nil {
			return fmt.Errorf("failed writing aggregated results: %w", err)
		}
	}

	err = validator.ValidateResultsDir(dir, expectedValidatorCount, expectedOwnerAddress, expectedOwnerNonce, expectedWithdrawAddress)
	if err != nil {
		return fmt.Errorf("failed validating results dir: %w", err)
	}

	return nil
}

func WriteAggregatedInitResults(dir string, depositDataArr []*wire.DepositDataCLI, keySharesArr []*wire.KeySharesCLI, proofs [][]*wire.SignedProof, logger *zap.Logger) error {
	// Write all to one JSON file
	depositFinalPath := fmt.Sprintf("%s/deposit_data.json", dir)
	logger.Info("💾 Writing deposit data json to file", zap.String("path", depositFinalPath))
	err := utils.WriteJSON(depositFinalPath, depositDataArr)
	if err != nil {
		logger.Error("Failed writing deposit data file: ", zap.Error(err), zap.String("path", depositFinalPath), zap.Any("deposits", depositDataArr))
		return err
	}
	keysharesFinalPath := fmt.Sprintf("%s/keyshares.json", dir)
	logger.Info("💾 Writing keyshares payload to file", zap.String("path", keysharesFinalPath))
	aggrKeySharesArr, err := initiator.GenerateAggregatesKeyshares(keySharesArr)
	if err != nil {
		return err
	}
	err = utils.WriteJSON(keysharesFinalPath, aggrKeySharesArr)
	if err != nil {
		logger.Error("Failed writing keyshares to file: ", zap.Error(err), zap.String("path", keysharesFinalPath), zap.Any("keyshares", keySharesArr))
		return err
	}
	proofsFinalPath := fmt.Sprintf("%s/proofs.json", dir)
	err = utils.WriteJSON(proofsFinalPath, proofs)
	if err != nil {
		logger.Error("Failed writing ceremony sig file: ", zap.Error(err), zap.String("path", proofsFinalPath), zap.Any("proofs", proofs))
		return err
	}

	return nil
}

func WriteKeysharesResult(keyShares *wire.KeySharesCLI, dir string) error {
	keysharesFinalPath := fmt.Sprintf("%s/keyshares.json", dir)
	err := utils.WriteJSON(keysharesFinalPath, keyShares)
	if err != nil {
		return fmt.Errorf("failed writing keyshares file: %w, %v", err, keyShares)
	}
	return nil
}

func WriteDepositResult(depositData *wire.DepositDataCLI, dir string) error {
	depositFinalPath := fmt.Sprintf("%s/deposit_data.json", dir)
	err := utils.WriteJSON(depositFinalPath, []*wire.DepositDataCLI{depositData})

	if err != nil {
		return fmt.Errorf("failed writing deposit data file: %w, %v", err, depositData)
	}
	return nil
}

func WriteProofs(proofs []*wire.SignedProof, dir string) error {
	finalPath := fmt.Sprintf("%s/proofs.json", dir)
	err := utils.WriteJSON(finalPath, proofs)
	if err != nil {
		return fmt.Errorf("failed writing data file: %w, %v", err, proofs)
	}
	return nil
}

func CreateDirIfNotExist(path string) error {
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			// Directory does not exist, try to create it
			if err := os.MkdirAll(path, os.ModePerm); err != nil {
				// Failed to create the directory
				return fmt.Errorf("😥 can't create %s: %w", path, err)
			}
		} else {
			// Some other error occurred
			return fmt.Errorf("😥 %s", err)
		}
	}
	return nil
}

// Wrapper around zap.Sync() that ignores EINVAL errors.
//
// See: https://github.com/uber-go/zap/issues/1093#issuecomment-1120667285
func Sync(logger *zap.Logger) error {
	err := logger.Sync()
	if !errors.Is(err, syscall.EINVAL) {
		return err
	}
	return nil
}

func CheckIfOperatorHTTPS(ops []wire.OperatorCLI) error {
	for _, op := range ops {
		addr, err := url.Parse(op.Addr)
		if err != nil {
			return fmt.Errorf("parsing IP address: %s, err: %w", op.Addr, err)
		}
		if addr.Scheme != "https" {
			return fmt.Errorf("only HTTPS scheme is allowed at operator address %s, got: %s", op.Addr, addr.Scheme)
		}
	}
	return nil
}

func IsUrl(str string) bool {
	u, err := url.Parse(str)
	return err == nil && u.Scheme != "" && u.Host != ""
}

// OpenPrivateKey reads an RSA key from file.
// If passwordFilePath is provided, treats privKeyPath as encrypted
func OpenPrivateKey(passwordFilePath, privKeyPath string) (*rsa.PrivateKey, error) {
	// check if a password string a valid path, then read password from the file
	if _, err := os.Stat(passwordFilePath); os.IsNotExist(err) {
		return nil, fmt.Errorf("😥 Password file doesn`t exist: %s", err)
	}
	encryptedRSAJSON, err := os.ReadFile(filepath.Clean(privKeyPath))
	if err != nil {
		return nil, fmt.Errorf("😥 Cant read operator's key file: %s", err)
	}
	keyStorePassword, err := os.ReadFile(filepath.Clean(passwordFilePath))
	if err != nil {
		return nil, fmt.Errorf("😥 Error reading password file: %s", err)
	}
	privateKey, err := crypto.DecryptRSAKeystore(encryptedRSAJSON, string(keyStorePassword))
	if err != nil {
		return nil, fmt.Errorf("😥 Error converting pem to priv key: %s", err)
	}
	return privateKey, nil
}

// ReadOperatorsInfoFile reads operators data from path
func ReadOperatorsInfoFile(operatorsInfoPath string, logger *zap.Logger) (wire.OperatorsCLI, error) {
	fmt.Printf("📖 looking operators info 'operators_info.json' file: %s \n", operatorsInfoPath)
	_, err := os.Stat(operatorsInfoPath)
	if os.IsNotExist(err) {
		return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
	}
	logger.Info("📖 reading operators info JSON file")
	operatorsInfoJSON, err := os.ReadFile(filepath.Clean(operatorsInfoPath))
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to read operator info file: %s", err)
	}
	var operators wire.OperatorsCLI
	err = json.Unmarshal(operatorsInfoJSON, &operators)
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to load operators: %s", err)
	}
	return operators, nil
}

// LoadOperators loads operators data from raw json or file path
func LoadOperators(logger *zap.Logger, operatorsInfo, operatorsInfoPath string) (wire.OperatorsCLI, error) {
	var operators wire.OperatorsCLI
	var err error
	if operatorsInfo != "" {
		err = json.Unmarshal([]byte(operatorsInfo), &operators)
		if err != nil {
			return nil, err
		}
	} else {
		operators, err = ReadOperatorsInfoFile(operatorsInfoPath, logger)
		if err != nil {
			return nil, err
		}
	}
	if operators == nil {
		return nil, fmt.Errorf("no information about operators is provided. Please use or raw JSON, or file")
	}
	// check that we use https
	if err := CheckIfOperatorHTTPS(operators); err != nil {
		return nil, err
	}
	return operators, nil
}

// SetGlobalLogger creates a logger
func SetGlobalLogger(cmd *cobra.Command, name, logFilePath, logLevel, logFormat, logLevelFormat string) (*zap.Logger, error) {
	// If the log file doesn't exist, create it
	_, err := os.OpenFile(filepath.Clean(logFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, err
	}
	if err := logging.SetGlobalLogger(logLevel, logFormat, logLevelFormat, &logging.LogFileOptions{FileName: logFilePath}); err != nil {
		return nil, fmt.Errorf("logging.SetGlobalLogger: %w", err)
	}
	logger := zap.L().Named(name)
	return logger, nil
}
