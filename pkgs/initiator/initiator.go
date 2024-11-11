package initiator

import (
	"bytes"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	kyber_dkg "github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/consts"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"
)

type VerifyMessageSignatureFunc func(pub *rsa.PublicKey, msg, sig []byte) error

// Initiator main structure for initiator
type Initiator struct {
	Logger                 *zap.Logger                // logger
	Client                 *req.Client                // http client
	Operators              wire.OperatorsCLI          // operators info mapping
	VerifyMessageSignature VerifyMessageSignatureFunc // function to verify signatures of incoming messages
	PrivateKey             *rsa.PrivateKey            // a unique initiator's RSA private key used for signing messages and identity
	Version                []byte
}

// GeneratePayload generates at initiator ssv smart contract payload using DKG result  received from operators participating in DKG ceremony
func (c *Initiator) generateSSVKeysharesPayload(operators []*spec.Operator, dkgResults []*spec.Result, reconstructedOwnerNonceMasterSig *bls.Sign, owner common.Address, nonce uint64) (*wire.KeySharesCLI, error) {
	sigOwnerNonce := reconstructedOwnerNonceMasterSig.Serialize()
	operatorIds := make([]uint64, 0)
	var pubkeys []byte
	var encryptedShares []byte
	for i := 0; i < len(dkgResults); i++ {
		// Data for forming share string
		pubkeys = append(pubkeys, dkgResults[i].SignedProof.Proof.SharePubKey...)
		encryptedShares = append(encryptedShares, dkgResults[i].SignedProof.Proof.EncryptedShare...)
		operatorIds = append(operatorIds, dkgResults[i].OperatorID)
	}

	// Create share string for ssv contract
	pubkeys = append(pubkeys, encryptedShares...)
	sigOwnerNonce = append(sigOwnerNonce, pubkeys...)

	operatorCount := len(dkgResults)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset

	if sharesExpectedLength != len(sigOwnerNonce) {
		return nil, fmt.Errorf("malformed ssv share data")
	}

	data := []*wire.Data{{
		ShareData: wire.ShareData{
			OwnerNonce:   nonce,
			OwnerAddress: owner.Hex(),
			PublicKey:    "0x" + hex.EncodeToString(dkgResults[0].SignedProof.Proof.ValidatorPubKey),
			Operators:    operators,
		},
		Payload: wire.Payload{
			PublicKey:   "0x" + hex.EncodeToString(dkgResults[0].SignedProof.Proof.ValidatorPubKey),
			OperatorIDs: operatorIds,
			SharesData:  "0x" + hex.EncodeToString(sigOwnerNonce),
		},
	}}

	ks := &wire.KeySharesCLI{}
	ks.Version = "v1.2.0"
	ks.Shares = data
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

func GenerateAggregatesKeyshares(keySharesArr []*wire.KeySharesCLI) (*wire.KeySharesCLI, error) {
	var data []*wire.Data
	for _, keyShares := range keySharesArr {
		data = append(data, keyShares.Shares...)
	}
	ks := &wire.KeySharesCLI{}
	ks.Version = "v1.2.0"
	ks.Shares = data
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

// New creates a main initiator structure
func New(operators wire.OperatorsCLI, logger *zap.Logger, ver string, certs []string, tlsInsecure bool) (*Initiator, error) {
	client := req.C()
	// set CA certificates
	if tlsInsecure {
		logger.Warn("Dangerous, not secure!!! No CA certificates provided at 'clientCACertPath'. TLS 'InsecureSkipVerify' is set to true, accepting any TLS certificates authorities.")
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
	} else {
		client.SetRootCertsFromFile(certs...)
	}
	// Set timeout for operator responses
	client.SetTimeout(30 * time.Second)
	privKey, _, err := spec_crypto.GenerateRSAKeys()
	if err != nil {
		return nil, fmt.Errorf("failed to generate RSA keys: %s", err)
	}
	c := &Initiator{
		Logger:                 logger,
		Client:                 client,
		Operators:              operators,
		PrivateKey:             privKey,
		VerifyMessageSignature: standardMessageVerification(operators),
		Version:                []byte(ver),
	}
	return c, nil
}

// ValidatedOperatorData validates operators information data before starting a DKG ceremony
func ValidatedOperatorData(ids []uint64, operators wire.OperatorsCLI) ([]*spec.Operator, error) {
	if err := utils.ValidateOpsLen(len(ids)); err != nil {
		return nil, err
	}

	ops := make([]*spec.Operator, len(ids))
	opMap := make(map[uint64]struct{})
	for i, id := range ids {
		if id == 0 {
			return nil, errors.New("operator ID cannot be 0")
		}
		op := operators.ByID(id)
		if op == nil {
			return nil, errors.New("operator is not in given operator data list")
		}
		_, exist := opMap[id]
		if exist {
			return nil, errors.New("operators ids should be unique in the list")
		}
		opMap[id] = struct{}{}

		pkBytes, err := spec_crypto.EncodeRSAPublicKey(op.PubKey)
		if err != nil {
			return nil, fmt.Errorf("can't encode public key err: %w", err)
		}
		ops[i] = &spec.Operator{
			ID:     op.ID,
			PubKey: pkBytes,
		}
	}
	sort.SliceIsSorted(ops, func(p, q int) bool {
		return ops[p].ID < ops[q].ID
	})
	return ops, nil
}

// messageFlowHandling main steps of DKG at initiator
func (c *Initiator) initMessageFlowHandling(init *spec.Init, id [24]byte, operators []*spec.Operator) ([][]byte, error) {
	c.Logger.Info("phase 1: sending init message to operators")
	exchangeMsgs, errs, err := c.SendInitMsg(id, init, operators)
	if err != nil {
		return nil, err
	}
	// check that all operators replied
	if err := checkThreshold(exchangeMsgs, errs, operators, operators, len(operators)); err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, exchangeMsgs, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 1: ✅ verified operator init responses signatures")
	c.Logger.Info("phase 2: ➡️ sending operator data (exchange messages) required for dkg")
	kyberMsgs, errs, err := c.SendExchangeMsgs(id, exchangeMsgs, operators)
	if err != nil {
		return nil, err
	}
	if err := checkThreshold(kyberMsgs, errs, operators, operators, len(operators)); err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, kyberMsgs, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator responses (deal messages) signatures")
	c.Logger.Info("phase 3: ➡️ sending deal dkg data to all operators")
	dkgResult, errs, err := c.SendKyberMsgs(id, kyberMsgs, operators)
	if err != nil {
		return nil, err
	}
	if err := checkThreshold(dkgResult, errs, operators, operators, len(operators)); err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, dkgResult, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	var finalResults [][]byte
	for _, res := range dkgResult {
		finalResults = append(finalResults, res)
	}
	c.Logger.Info("phase 2: ✅ verified operator dkg results signatures")
	return finalResults, nil
}

func (c *Initiator) ResignMessageFlowHandling(signedResign *wire.SignedResign, id [24]byte, operators []*spec.Operator) ([][][]byte, error) {
	// reqIDtracker is used to track if all ceremony are in the responses in the expected order
	reqIDs := make([][24]byte, 0)
	for _, msg := range signedResign.Messages {
		msgID, err := utils.GetReqIDfromMsg(msg, id)
		if err != nil {
			return nil, err
		}
		reqIDs = append(reqIDs, msgID)
	}
	resignResult, errs, err := c.SendResignMsg(id, signedResign, operators)
	if err != nil {
		return nil, err
	}
	// sanity check
	if err := checkThreshold(resignResult, errs, operators, operators, len(operators)); err != nil {
		return nil, err
	}
	expectedNumOfResponses := len(signedResign.Messages)
	// allResults is a map of operatorID -> [ceremony][response]
	allResults := make(map[uint64][][]byte)
	for operatorID, res := range resignResult {
		allRes, err := utils.UnflattenResponseMsgs(res)
		if err != nil {
			return nil, err
		}
		if len(allRes) != expectedNumOfResponses {
			return nil, fmt.Errorf("operator %d returned %d responses, expected %d", operatorID, len(allRes), expectedNumOfResponses)
		}
		allResults[operatorID] = allRes
	}
	// results is a 3d array of [ceremony][operator][response]
	var results [][][]byte
	for i := 0; i < expectedNumOfResponses; i++ {
		instanceResignResultMap := make(map[uint64][]byte)
		var instanceResignResultArr [][]byte
		for operatorID, res := range allResults {
			instanceResignResultMap[operatorID] = res[i]
			instanceResignResultArr = append(instanceResignResultArr, res[i])
		}
		err = verifyMessageSignatures(reqIDs[i], instanceResignResultMap, c.VerifyMessageSignature)
		if err != nil {
			return nil, fmt.Errorf("failed to verify message signatures for ceremony %d: %w", i, err)
		}
		results = append(results, instanceResignResultArr)
	}
	c.Logger.Info("✅ verified operator response signatures")

	return results, nil
}

func (c *Initiator) ReshareMessageFlowHandling(id [24]byte, signedReshare *wire.SignedReshare) ([][][]byte, error) {
	allOps, err := utils.JoinSets(signedReshare.Messages[0].Reshare.OldOperators, signedReshare.Messages[0].Reshare.NewOperators)
	if err != nil {
		return nil, err
	}
	// reqIDtracker is used to track if all ceremony are in the responses in the expected order
	reqIDs := make([][24]byte, 0)
	for _, msg := range signedReshare.Messages {
		msgID, err := utils.GetReqIDfromMsg(msg, id)
		if err != nil {
			return nil, err
		}
		reqIDs = append(reqIDs, msgID)
	}
	c.Logger.Info("sending signed reshare message to all operators")
	var errs map[uint64]error
	exchangeMsgs, errs, err := c.SendReshareMsg(id, signedReshare, allOps)
	if err != nil {
		return nil, err
	}
	// check that all new operators and threshold of old operators replied without errors
	if err := checkThreshold(exchangeMsgs, errs, signedReshare.Messages[0].Reshare.OldOperators, signedReshare.Messages[0].Reshare.NewOperators, int(signedReshare.Messages[0].Reshare.OldT)); err != nil {
		return nil, err
	}
	numOfCeremonies := len(signedReshare.Messages)
	// allResults is a map of operatorID -> [ceremony][response]
	allResults := make(map[uint64][][]byte)
	for operatorID, res := range exchangeMsgs {
		allRes, err := utils.UnflattenResponseMsgs(res)
		if err != nil {
			return nil, err
		}
		if len(allRes) != numOfCeremonies {
			return nil, fmt.Errorf("operator %d returned %d responses, expected %d", operatorID, len(allRes), numOfCeremonies)
		}
		allResults[operatorID] = allRes
	}
	// Operators have created instances of all ceremonies and sent back all exhcnage messages to initiator
	c.Logger.Info("received exchange message responses for all ceremonies")
	c.Logger.Info("continuing with all ceremonies one by one")
	// finalResults contains result bytes for each operator for each ceremony
	var finalResults [][][]byte
	for i := 0; i < numOfCeremonies; i++ {
		reqID := reqIDs[i]
		instanceExchangeMsgs := make(map[uint64][]byte)
		for operatorID, res := range allResults {
			instanceExchangeMsgs[operatorID] = res[i]
		}
		err = verifyMessageSignatures(reqID, instanceExchangeMsgs, c.VerifyMessageSignature)
		if err != nil {
			return nil, err
		}
		kyberMsgs, errs, err := c.SendExchangeMsgs(reqID, instanceExchangeMsgs, allOps)
		if err != nil {
			return nil, err
		}
		// check that all new operators and threshold of old operators replied without errors
		if err := checkThreshold(kyberMsgs, errs, signedReshare.Messages[0].Reshare.OldOperators, signedReshare.Messages[0].Reshare.NewOperators, int(signedReshare.Messages[0].Reshare.OldT)); err != nil {
			return nil, err
		}
		err = verifyMessageSignatures(reqID, kyberMsgs, c.VerifyMessageSignature)
		if err != nil {
			return nil, err
		}
		dkgResult, errs, err := c.SendKyberMsgs(reqID, kyberMsgs, signedReshare.Messages[0].Reshare.NewOperators)
		if err != nil {
			return nil, err
		}
		// check that all new operators replied without errors
		if err := checkThreshold(dkgResult, errs, signedReshare.Messages[0].Reshare.NewOperators, signedReshare.Messages[0].Reshare.NewOperators, len(signedReshare.Messages[0].Reshare.NewOperators)); err != nil {
			return nil, err
		}
		for id := range dkgResult {
			c.Logger.Info("DKG Reshare results", zap.Any("id", id))
		}
		err = verifyMessageSignatures(reqID, dkgResult, c.VerifyMessageSignature)
		if err != nil {
			return nil, err
		}
		var ceremonyResult [][]byte
		for _, res := range dkgResult {
			ceremonyResult = append(ceremonyResult, res)
		}
		finalResults = append(finalResults, ceremonyResult)
	}
	c.Logger.Info("all ceremonies completed")
	return finalResults, nil
}

// StartDKG starts DKG ceremony at initiator with requested parameters
func (c *Initiator) StartDKG(id [24]byte, withdraw []byte, ids []uint64, network eth2_key_manager_core.Network, owner common.Address, nonce, amount uint64) (*wire.DepositDataCLI, *wire.KeySharesCLI, []*wire.SignedProof, error) {
	if len(withdraw) != len(common.Address{}) {
		return nil, nil, nil, fmt.Errorf("incorrect withdrawal address length")
	}
	ops, err := ValidatedOperatorData(ids, c.Operators)
	if err != nil {
		return nil, nil, nil, err
	}
	instanceIDField := zap.String("Ceremony ID", hex.EncodeToString(id[:]))
	c.Logger.Info("🚀 Starting init dkg ceremony", zap.Uint64s("operator IDs", ids))

	threshold := utils.GetThreshold(ids)
	// make init message
	init := &spec.Init{
		Operators:             ops,
		T:                     uint64(threshold),
		WithdrawalCredentials: withdraw,
		Fork:                  network.GenesisForkVersion(),
		Owner:                 owner,
		Nonce:                 nonce,
		Amount:                amount,
	}
	c.Logger.Info("Outgoing init request fields",
		zap.String("network", hex.EncodeToString(init.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(init.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(init.Owner[:])),
		zap.Uint64("nonce", init.Nonce),
		zap.Any("operator IDs", ids))
	c.Logger = c.Logger.With(instanceIDField)
	dkgResultsBytes, err := c.initMessageFlowHandling(init, id, ops)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.CreateCeremonyResults(dkgResultsBytes, id, init.Operators, init.WithdrawalCredentials, nil, init.Fork, init.Owner, init.Nonce, phase0.Gwei(init.Amount))
}

func (c *Initiator) StartResigning(id [24]byte, signedResign *wire.SignedResign) ([]*wire.DepositDataCLI, []*wire.KeySharesCLI, [][]*wire.SignedProof, error) {
	if len(signedResign.Messages) == 0 {
		return nil, nil, nil, errors.New("no resign messages")
	}
	resignIDMap := make(map[[24]byte]*spec.Resign)
	for _, msg := range signedResign.Messages {
		msgID, err := utils.GetReqIDfromMsg(msg, id)
		if err != nil {
			return nil, nil, nil, err
		}
		resignIDMap[msgID] = msg.Resign
	}
	var operatorIDs []uint64
	for _, op := range signedResign.Messages[0].Operators {
		operatorIDs = append(operatorIDs, op.ID)
	}
	c.Logger.Info("🚀 Starting resign dkg ceremony", zap.Uint64s("operator IDs", operatorIDs))
	c.Logger.Info("Outgoing resign request fields",
		zap.String("network", hex.EncodeToString(signedResign.Messages[0].Resign.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(signedResign.Messages[0].Resign.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(signedResign.Messages[0].Resign.Owner[:])),
		zap.Any("operators IDs", signedResign.Messages[0].Operators),
		zap.String("EIP1271 owner signature", hex.EncodeToString(signedResign.Signature)))
	for _, msg := range signedResign.Messages {
		for _, proof := range msg.Proofs {
			c.Logger.Info("Loaded proof",
				zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
				zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
				zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
				zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
				zap.String("Signature", hex.EncodeToString(proof.Signature)))
		}
	}
	allResults, err := c.ResignMessageFlowHandling(
		signedResign,
		id,
		signedResign.Messages[0].Operators)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.createBulkResults(allResults, signedResign, resignIDMap)
}

func (c *Initiator) CreateCeremonyResults(
	resultsBytes [][]byte,
	id [24]byte,
	ops []*spec.Operator,
	withdrawalCredentials []byte,
	validatorPK []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	amount phase0.Gwei,
) (*wire.DepositDataCLI, *wire.KeySharesCLI, []*wire.SignedProof, error) {
	dkgResults, err := c.parseDKGResultsFromBytes(resultsBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("🏁 DKG ceremony completed, validating results...")
	// only for resigning and resharing
	if validatorPK != nil {
		_, _, _, err = spec.ValidateResults(
			ops,
			withdrawalCredentials,
			validatorPK,
			fork,
			ownerAddress,
			nonce,
			amount,
			id,
			dkgResults)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	depositDataJson, keyshares, err := c.processDKGResultResponse(dkgResults, id, ops, withdrawalCredentials, fork, ownerAddress, nonce, amount)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ verified master signature for ssv contract data")
	if err := crypto.ValidateDepositDataCLI(depositDataJson, common.BytesToAddress(withdrawalCredentials)); err != nil {
		return nil, nil, nil, err
	}
	if err := crypto.ValidateKeysharesCLI(keyshares, ops, ownerAddress, nonce, depositDataJson.PubKey); err != nil {
		return nil, nil, nil, err
	}
	// sending back to operators results
	depositData, err := json.Marshal(depositDataJson)
	if err != nil {
		return nil, nil, nil, err
	}
	keysharesData, err := json.Marshal(keyshares)
	if err != nil {
		return nil, nil, nil, err
	}
	var proofsArray []*wire.SignedProof
	for _, res := range dkgResults {
		proofsArray = append(proofsArray, &wire.SignedProof{SignedProof: res.SignedProof})
	}
	proofsData, err := json.Marshal(proofsArray)
	if err != nil {
		return nil, nil, nil, err
	}
	resultMsg := &wire.ResultData{
		Operators:     ops,
		Identifier:    id,
		DepositData:   depositData,
		KeysharesData: keysharesData,
		Proofs:        proofsData,
	}
	err = c.sendResult(resultMsg, ops, consts.API_RESULTS_URL, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("🤖 Error storing results at operators %w", err)
	}
	return depositDataJson, keyshares, proofsArray, nil
}

func (c *Initiator) StartResharing(id [24]byte, signedReshare *wire.SignedReshare) ([]*wire.DepositDataCLI, []*wire.KeySharesCLI, [][]*wire.SignedProof, error) {
	if len(signedReshare.Messages) == 0 {
		return nil, nil, nil, errors.New("no reshare messages")
	}
	reshareIDMap := make(map[[24]byte]*spec.Reshare)
	for _, msg := range signedReshare.Messages {
		msgID, err := utils.GetReqIDfromMsg(msg, id)
		if err != nil {
			return nil, nil, nil, err
		}
		reshareIDMap[msgID] = msg.Reshare
	}
	oldOperatorIDs := make([]uint64, 0)
	for _, op := range signedReshare.Messages[0].Reshare.OldOperators {
		oldOperatorIDs = append(oldOperatorIDs, op.ID)
	}
	newOperatorIDs := make([]uint64, 0)
	for _, op := range signedReshare.Messages[0].Reshare.NewOperators {
		newOperatorIDs = append(newOperatorIDs, op.ID)
	}
	c.Logger.Info("🚀 Starting resharing ceremony", zap.Uint64s("old operator IDs", oldOperatorIDs), zap.Uint64s("new operator IDs", newOperatorIDs))
	c.Logger.Info("Outgoing reshare request fields",
		zap.Any("Old operator IDs", oldOperatorIDs),
		zap.Any("New operator IDs", newOperatorIDs),
		zap.String("network", hex.EncodeToString(signedReshare.Messages[0].Reshare.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(signedReshare.Messages[0].Reshare.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(signedReshare.Messages[0].Reshare.Owner[:])),
		zap.String("EIP1271 owner signature", hex.EncodeToString(signedReshare.Signature)))
	resultsBytes, err := c.ReshareMessageFlowHandling(id, signedReshare)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.createBulkResults(resultsBytes, signedReshare, reshareIDMap)
}

// processDKGResultResponseInitial deserializes incoming DKG result messages from operators after successful initiation ceremony
func (c *Initiator) processDKGResultResponse(dkgResults []*spec.Result,
	requestID [24]byte,
	ops []*spec.Operator,
	withdrawalCredentials []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64,
	amount phase0.Gwei) (*wire.DepositDataCLI, *wire.KeySharesCLI, error) {
	// check results sorted by operatorID
	sorted := sort.SliceIsSorted(dkgResults, func(p, q int) bool {
		return dkgResults[p].OperatorID < dkgResults[q].OperatorID
	})
	if !sorted {
		return nil, nil, fmt.Errorf("slice is not sorted")
	}
	validatorPK, err := spec.RecoverValidatorPKFromResults(dkgResults)
	if err != nil {
		return nil, nil, err
	}
	_, depositData, masterSigOwnerNonce, err := spec.ValidateResults(ops, withdrawalCredentials, validatorPK, fork, ownerAddress, nonce, amount, requestID, dkgResults)
	if err != nil {
		return nil, nil, err
	}
	network, err := spec_crypto.GetNetworkByFork(fork)
	if err != nil {
		return nil, nil, err
	}
	depositDataJson, err := crypto.BuildDepositDataCLI(network, depositData, wire.DepositCliVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create deposit data json: %w", err)
	}
	c.Logger.Info("✅ deposit data was successfully reconstructed")
	keyshares, err := c.generateSSVKeysharesPayload(ops, dkgResults, masterSigOwnerNonce, ownerAddress, nonce)
	if err != nil {
		return nil, nil, err
	}
	return depositDataJson, keyshares, nil
}

func (c *Initiator) parseDKGResultsFromBytes(responseResult [][]byte) (dkgResults []*spec.Result, finalErr error) {
	for i := 0; i < len(responseResult); i++ {
		msg := responseResult[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		if err := verifyMessageType(tsp, wire.OutputMessageType); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		result := &spec.Result{}
		if err := result.UnmarshalSSZ(tsp.Message.Data); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		dkgResults = append(dkgResults, result)
	}
	if finalErr != nil {
		return nil, finalErr
	}
	// sort the results by operatorID
	sort.SliceStable(dkgResults, func(i, j int) bool {
		return dkgResults[i].OperatorID < dkgResults[j].OperatorID
	})
	for i := 0; i < len(dkgResults); i++ {
		if len(dkgResults[i].SignedProof.Proof.ValidatorPubKey) == 0 ||
			!bytes.Equal(dkgResults[i].SignedProof.Proof.ValidatorPubKey,
				dkgResults[0].SignedProof.Proof.ValidatorPubKey) {
			return nil, fmt.Errorf("operator %d sent wrong validator public key: %x", dkgResults[i].OperatorID, dkgResults[i].SignedProof.Proof.ValidatorPubKey)
		}
	}
	return dkgResults, nil
}

// SendInitMsg sends initial DKG ceremony message to participating operators from initiator
func (c *Initiator) SendInitMsg(id [24]byte, init *spec.Init, operators []*spec.Operator) (results map[uint64][]byte, errs map[uint64]error, err error) {
	signedInitMsgBts, err := c.prepareAndSignMessage(init, wire.InitMessageType, id, c.Version)
	if err != nil {
		return nil, nil, err
	}
	results, errs = c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, operators)
	return results, errs, nil
}

func (c *Initiator) SendResignMsg(id [24]byte, resign *wire.SignedResign, operators []*spec.Operator) (results map[uint64][]byte, errs map[uint64]error, err error) {
	signedResignMsgBts, err := c.prepareAndSignMessage(resign, wire.SignedResignMessageType, id, c.Version)
	if err != nil {
		return nil, nil, err
	}
	results, errs = c.SendToAll(consts.API_RESIGN_URL, signedResignMsgBts, operators)
	return results, errs, nil
}

func (c *Initiator) SendReshareMsg(id [24]byte, reshare *wire.SignedReshare, operators []*spec.Operator) (results map[uint64][]byte, errs map[uint64]error, err error) {
	signedReshareMsgBts, err := c.prepareAndSignMessage(reshare, wire.SignedReshareMessageType, id, c.Version)
	if err != nil {
		return nil, nil, err
	}
	results, errs = c.SendToAll(consts.API_RESHARE_URL, signedReshareMsgBts, operators)
	return results, errs, nil
}

// SendExchangeMsgs sends combined exchange messages to each operator participating in DKG ceremony
func (c *Initiator) SendExchangeMsgs(id [24]byte, exchangeMsgs map[uint64][]byte, operators []*spec.Operator) (results map[uint64][]byte, errs map[uint64]error, err error) {
	mltpl, err := makeMultipleSignedTransports(c.PrivateKey, id, exchangeMsgs)
	if err != nil {
		return nil, nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}
	results, errs = c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
	return results, errs, nil
}

func (c *Initiator) SendExchangeMsgsReshare(id [24]byte, exchangeMsgs map[uint64][]byte, operators []*spec.Operator) (results map[uint64][]byte, errs map[uint64]error, err error) {
	mltpl, err := makeMultipleSignedTransports(c.PrivateKey, id, exchangeMsgs)
	if err != nil {
		return nil, nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}
	results, errs = c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
	return results, errs, nil
}

// SendKyberMsgs sends combined kyber messages to each operator participating in DKG ceremony
func (c *Initiator) SendKyberMsgs(id [24]byte, kyberDeals map[uint64][]byte, operators []*spec.Operator) (results map[uint64][]byte, errs map[uint64]error, err error) {
	mltpl2, err := makeMultipleSignedTransports(c.PrivateKey, id, kyberDeals)
	if err != nil {
		return nil, nil, err
	}
	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}
	results, errs = c.SendToAll(consts.API_DKG_URL, mltpl2byts, operators)
	return results, errs, nil
}

func (c *Initiator) sendResult(resData *wire.ResultData, operators []*spec.Operator, method string, id [24]byte) error {
	signedMsgBts, err := c.prepareAndSignMessage(resData, wire.ResultMessageType, id, c.Version)
	if err != nil {
		return fmt.Errorf("failed to prepare message: %w", err)
	}
	_, errs := c.SendToAll(method, signedMsgBts, operators)
	if len(errs) != 0 {
		var finalErr error
		for id, err := range errs {
			if err := errors.Join(finalErr, fmt.Errorf("operator %d, error: %w", id, err)); err != nil {
				return fmt.Errorf("failed to join operator errors: %w", err)
			}
		}
		return finalErr
	}
	return nil
}

func (c *Initiator) Ping(ips []string) error {
	resc := make(chan wire.PongResult, len(ips))
	for _, ip := range ips {
		go func(ip string) {
			resdata, err := c.GetAndCollect(wire.OperatorCLI{Addr: ip}, consts.API_HEALTH_CHECK_URL)
			resc <- wire.PongResult{
				IP:     ip,
				Err:    err,
				Result: resdata,
			}
		}(ip)
	}
	for i := 0; i < len(ips); i++ {
		res := <-resc
		err := c.processPongMessage(res)
		if err != nil {
			c.Logger.Error("🔴 operator not healthy: ", zap.Error(err), zap.String("IP", res.IP))
			continue
		}
	}
	return nil
}

func (c *Initiator) prepareAndSignMessage(msg wire.SSZMarshaller, msgType wire.TransportType, identifier [24]byte, v []byte) ([]byte, error) {
	// Marshal the provided message
	marshaledMsg, err := msg.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	pub, err := spec_crypto.EncodeRSAPublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	// Create the transport message
	transportMsg := &wire.Transport{
		Type:       msgType,
		Identifier: identifier,
		Data:       marshaledMsg,
		Version:    v,
	}

	// Marshal the transport message
	tssz, err := transportMsg.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	// Sign the message
	sig, err := spec_crypto.SignRSA(c.PrivateKey, tssz)
	if err != nil {
		return nil, err
	}

	// Create and marshal the signed transport message
	signedTransportMsg := &wire.SignedTransport{
		Message:   transportMsg,
		Signer:    pub, // Ensure this value is correctly set as per your application logic
		Signature: sig,
	}
	return signedTransportMsg.MarshalSSZ()
}

func (c *Initiator) processPongMessage(res wire.PongResult) error {
	if res.Err != nil {
		return res.Err
	}
	signedPongMsg := &wire.SignedTransport{}
	if err := signedPongMsg.UnmarshalSSZ(res.Result); err != nil {
		if strings.Contains(err.Error(), "incorrect offset") {
			return fmt.Errorf("%w, operator probably of old version, please upgrade", err)
		}
		// in case we received error message, try unmarshall
		errString, err := wire.ParseAsError(res.Result)
		if err == nil {
			return fmt.Errorf("cant parse error message: %w", err)
		}
		return fmt.Errorf("operator returned error: %s", errString)
	}
	// Validate that incoming message is an pong message
	if err := verifyMessageType(signedPongMsg, wire.PongMessageType); err != nil {
		return err
	}
	pong := &wire.Pong{}
	if err := pong.UnmarshalSSZ(signedPongMsg.Message.Data); err != nil {
		return fmt.Errorf("🆘 cant unmarshall pong message, probably old version, please upgrade: %w", err)

	}
	pongBytes, err := signedPongMsg.Message.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("error marshalling signedPongMsg: %w", err)
	}
	pub, err := spec_crypto.ParseRSAPublicKey(pong.PubKey)
	if err != nil {
		return fmt.Errorf("cant parse RSA public key from pong message: %w", err)
	}
	// Check that we got pong with correct pub
	if err := spec_crypto.VerifyRSA(pub, pongBytes, signedPongMsg.Signature); err != nil {
		return fmt.Errorf("operator sent pong with wrong RSA public key %w", err)
	}
	if pong.Multisig {
		if pong.EthClientConnected {
			c.Logger.Info("🟢 operator online and healthy: multisig ready 👌 and connected to ethereum network ⛓️", zap.Uint64("ID", pong.ID), zap.String("IP", res.IP), zap.String("Version", string(signedPongMsg.Message.Version)), zap.String("Public key", string(pong.PubKey)))
		} else {
			c.Logger.Info("🟢 operator online and healthy: multisig ready 👌 but NOT connected to ethereum network 🚫", zap.Uint64("ID", pong.ID), zap.String("IP", res.IP), zap.String("Version", string(signedPongMsg.Message.Version)), zap.String("Public key", string(pong.PubKey)))
		}
	} else {
		c.Logger.Error("🔴 operator online: but NOT multisig ready", zap.Uint64("ID", pong.ID), zap.String("IP", res.IP), zap.String("Version", string(signedPongMsg.Message.Version)), zap.String("Public key", string(pong.PubKey)))
	}
	return nil
}

func (c *Initiator) ConstructReshareMessage(oldOperatorIDs, newOperatorIDs []uint64, validatorPub []byte, ethnetwork eth2_key_manager_core.Network, withdrawCreds []byte, owner common.Address, nonce, amount uint64, proofsData []*spec.SignedProof) (*wire.ReshareMessage, error) {
	if len(proofsData) == 0 {
		return nil, fmt.Errorf("🤖 proofs are empty")
	}
	oldOps, err := ValidatedOperatorData(oldOperatorIDs, c.Operators)
	if err != nil {
		return nil, err
	}
	// validate proofs
	for i, op := range oldOps {
		if err := spec.ValidateCeremonyProof(proofsData[0].Proof.ValidatorPubKey, op, *proofsData[i]); err != nil {
			return nil, err
		}
	}
	newOps, err := ValidatedOperatorData(newOperatorIDs, c.Operators)
	if err != nil {
		return nil, err
	}
	if !spec.UniqueAndOrderedOperators(oldOps) {
		return nil, fmt.Errorf("old operators are not ordered or unique")
	}
	if !spec.UniqueAndOrderedOperators(newOps) {
		return nil, fmt.Errorf("new operators are not ordered or unique")
	}
	// Construct reshare message
	reshare := &spec.Reshare{
		ValidatorPubKey:       validatorPub,
		OldOperators:          oldOps,
		NewOperators:          newOps,
		OldT:                  uint64(len(oldOperatorIDs) - ((len(oldOperatorIDs) - 1) / 3)),
		NewT:                  uint64(len(newOperatorIDs) - ((len(newOperatorIDs) - 1) / 3)),
		Fork:                  ethnetwork.GenesisForkVersion(),
		WithdrawalCredentials: withdrawCreds,
		Owner:                 owner,
		Nonce:                 nonce,
		Amount:                amount,
	}
	return &wire.ReshareMessage{
		Reshare: reshare,
		Proofs:  proofsData,
	}, nil
}

func (c *Initiator) ConstructResignMessage(operatorIDs []uint64, validatorPub []byte, ethnetwork eth2_key_manager_core.Network, withdrawCreds []byte, owner common.Address, nonce, amount uint64, proofsData []*spec.SignedProof) (*wire.ResignMessage, error) {
	if len(proofsData) == 0 {
		return nil, fmt.Errorf("🤖 unmarshaled proofs object is empty")
	}
	ops, err := ValidatedOperatorData(operatorIDs, c.Operators)
	if err != nil {
		return nil, err
	}
	// validate proofs
	for i, op := range ops {
		if err := spec.ValidateCeremonyProof(proofsData[0].Proof.ValidatorPubKey, op, *proofsData[i]); err != nil {
			return nil, err
		}
	}
	// create resign message
	resign := spec.Resign{ValidatorPubKey: validatorPub,
		Fork:                  ethnetwork.GenesisForkVersion(),
		WithdrawalCredentials: withdrawCreds,
		Owner:                 owner,
		Nonce:                 nonce,
		Amount:                amount}
	return &wire.ResignMessage{
		Operators: ops,
		Resign:    &resign,
		Proofs:    proofsData,
	}, nil
}

func checkThreshold(responses map[uint64][]byte, errs map[uint64]error, oldOperators, newOperators []*spec.Operator, threshold int) error {
	allOps, err := utils.JoinSets(oldOperators, newOperators)
	if err != nil {
		return err
	}
	if len(responses)+len(errs) != len(allOps) {
		return fmt.Errorf("not enough replies from operators: exp %d, got %d", len(allOps), len(responses)+len(errs))
	}
	// all newly introduced operators should reply
	var finalErr error
	for _, op := range newOperators {
		if err, ok := errs[op.ID]; ok {
			if strings.Contains(err.Error(), "invalid ssz encoding") {
				err = fmt.Errorf("%w, operator probably of old version, please upgrade", err)
			}
			finalErr = errors.Join(finalErr, fmt.Errorf("error: %w", err))
		}
	}
	if finalErr != nil {
		return fmt.Errorf("some new operators returned errors, cant continue: %w", finalErr)
	}
	// we expect threshold of old operator responses
	i := 0
	for _, op := range oldOperators {
		if _, ok := responses[op.ID]; ok {
			i++
		}
	}
	if i < threshold {
		for _, err := range errs {
			finalErr = errors.Join(finalErr, fmt.Errorf("error: %w", err))
		}
		return fmt.Errorf("less than threshold of operators replied: threshold %d, errors %d, %w", threshold, len(errs), finalErr)
	}
	return nil
}

func (c *Initiator) createBulkResults(resultsBytes [][][]byte, signedMsg, msgIDMap interface{}) ([]*wire.DepositDataCLI, []*wire.KeySharesCLI, [][]*wire.SignedProof, error) {
	bulkDepositData := []*wire.DepositDataCLI{}
	bulkKeyShares := []*wire.KeySharesCLI{}
	bulkProofs := [][]*wire.SignedProof{}
	for _, ceremonyResult := range resultsBytes {
		dkgResults, err := c.parseDKGResultsFromBytes(ceremonyResult)
		if err != nil {
			return nil, nil, nil, err
		}
		reqID := dkgResults[0].RequestID
		depositData := &wire.DepositDataCLI{}
		keyShares := &wire.KeySharesCLI{}
		Proofs := []*wire.SignedProof{}
		var expectedValidatorPubKey []byte
		switch signedMsg := signedMsg.(type) {
		case *wire.SignedResign:
			msgIDMap := msgIDMap.(map[[24]byte]*spec.Resign)
			expectedValidatorPubKey = msgIDMap[reqID].ValidatorPubKey
			depositData, keyShares, Proofs, err = c.CreateCeremonyResults(ceremonyResult, reqID, signedMsg.Messages[0].Operators, signedMsg.Messages[0].Resign.WithdrawalCredentials, expectedValidatorPubKey, signedMsg.Messages[0].Resign.Fork, signedMsg.Messages[0].Resign.Owner, msgIDMap[reqID].Nonce, phase0.Gwei(msgIDMap[reqID].Amount))
			if err != nil {
				return nil, nil, nil, err
			}
		case *wire.SignedReshare:
			msgIDMap := msgIDMap.(map[[24]byte]*spec.Reshare)
			expectedValidatorPubKey = msgIDMap[reqID].ValidatorPubKey
			depositData, keyShares, Proofs, err = c.CreateCeremonyResults(ceremonyResult, reqID, signedMsg.Messages[0].Reshare.NewOperators, signedMsg.Messages[0].Reshare.WithdrawalCredentials, expectedValidatorPubKey, signedMsg.Messages[0].Reshare.Fork, signedMsg.Messages[0].Reshare.Owner, msgIDMap[reqID].Nonce, phase0.Gwei(msgIDMap[reqID].Amount))
			if err != nil {
				return nil, nil, nil, err
			}
		}
		for _, res := range dkgResults {
			if !bytes.Equal(res.RequestID[:], reqID[:]) {
				return nil, nil, nil, fmt.Errorf("request ID mismatch")
			}
			if !bytes.Equal(res.SignedProof.Proof.ValidatorPubKey, expectedValidatorPubKey) {
				return nil, nil, nil, fmt.Errorf("validator pub key mismatch")
			}
		}
		bulkDepositData = append(bulkDepositData, depositData)
		bulkKeyShares = append(bulkKeyShares, keyShares)
		bulkProofs = append(bulkProofs, Proofs)
	}
	return bulkDepositData, bulkKeyShares, bulkProofs, nil
}

func verifyMessageType(tsp *wire.SignedTransport, expectedType wire.TransportType) error {
	if tsp.Message.Type != expectedType {
		if tsp.Message.Type == wire.ErrorMessageType {
			return fmt.Errorf("dkg protocol failed with %s", string(tsp.Message.Data))
		}
		if tsp.Message.Type == wire.KyberMessageType {
			kyberMsg := &wire.KyberMessage{}
			if err := kyberMsg.UnmarshalSSZ(tsp.Message.Data); err != nil {
				return err
			}
			switch kyberMsg.Type {
			// if we are not in fastsync, we expect only complaints
			case wire.KyberResponseBundleMessageType:
				bundle, err := wire.DecodeResponseBundle(kyberMsg.Data)
				if err != nil {
					return err
				}
				return fmt.Errorf("dkg protocol failed with response complaints: %v", bundle)
			case wire.KyberJustificationBundleMessageType:
				bundle, err := wire.DecodeJustificationBundle(kyberMsg.Data, kyber_bls12381.NewBLS12381Suite().G1().(kyber_dkg.Suite))
				if err != nil {
					return err
				}
				return fmt.Errorf("dkg protocol failed with justification message, which is unexpected: %v", bundle)
			default:
				return fmt.Errorf("received message with wrong type %s ", kyberMsg.Type)
			}
		}
	}
	return nil
}
