package initiator

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"crypto/tls"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"
	"github.com/ssvlabs/ssv-dkg/pkgs/consts"
	"github.com/ssvlabs/ssv-dkg/pkgs/crypto"
	"github.com/ssvlabs/ssv-dkg/pkgs/utils"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	spec_crypto "github.com/ssvlabs/dkg-spec/crypto"
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
	ks.Version = "DKG - " + string(c.Version)
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
	ks.Version = keySharesArr[0].Version
	ks.Shares = data
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

// New creates a main initiator structure
func New(operators wire.OperatorsCLI, logger *zap.Logger, ver string, certs []string) (*Initiator, error) {
	client := req.C()
	// set CA certificates if any
	if len(certs) > 0 {
		client.SetRootCertsFromFile(certs...)
	} else {
		client.SetTLSClientConfig(&tls.Config{InsecureSkipVerify: true})
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
			return nil, fmt.Errorf("can't encode public key err: %v", err)
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

func (c *Initiator) ResignMessageFlowHandling(rMsg *wire.ResignMessage, id [24]byte, operators []*spec.Operator) ([][]byte, error) {
	dkgResult, errs, err := c.SendResignMsg(id, rMsg, operators)
	if err != nil {
		return nil, err
	}
	// sanity check
	if err := checkThreshold(dkgResult, errs, operators, operators, len(operators)); err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, dkgResult, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("✅ verified operator response signatures")
	var results [][]byte
	for _, res := range dkgResult {
		results = append(results, res)
	}
	return results, nil
}

func (c *Initiator) messageFlowHandlingReshare(id [24]byte, reshareMsg *wire.ReshareMessage) ([][]byte, error) {
	c.Logger.Info("phase 1: sending reshare message to all operators")
	allOps, err := utils.JoinSets(reshareMsg.SignedReshare.Reshare.OldOperators, reshareMsg.SignedReshare.Reshare.NewOperators)
	if err != nil {
		return nil, err
	}
	var errs map[uint64]error
	exchangeMsgs, errs, err := c.SendReshareMsg(id, reshareMsg, allOps)
	if err != nil {
		return nil, err
	}
	// check that all new operators and threshold of old operators replied without errors
	if err := checkThreshold(exchangeMsgs, errs, reshareMsg.SignedReshare.Reshare.OldOperators, reshareMsg.SignedReshare.Reshare.NewOperators, int(reshareMsg.SignedReshare.Reshare.OldT)); err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, exchangeMsgs, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 1: ✅ verified operator resharing responses signatures")
	c.Logger.Info("phase 2: ➡️ sending operator data (exchange messages) required for dkg")
	kyberMsgs, errs, err := c.SendExchangeMsgs(id, exchangeMsgs, allOps)
	if err != nil {
		return nil, err
	}
	// check that all new operators and threshold of old operators replied without errors
	if err := checkThreshold(kyberMsgs, errs, reshareMsg.SignedReshare.Reshare.OldOperators, reshareMsg.SignedReshare.Reshare.NewOperators, int(reshareMsg.SignedReshare.Reshare.OldT)); err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, kyberMsgs, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified old operator responses (deal messages) signatures")
	c.Logger.Info("phase 3: ➡️ sending deal dkg data to new operators")
	dkgResult, errs, err := c.SendKyberMsgs(id, kyberMsgs, reshareMsg.SignedReshare.Reshare.NewOperators)
	if err != nil {
		return nil, err
	}
	// check that all new operators replied without errors
	if err := checkThreshold(dkgResult, errs, reshareMsg.SignedReshare.Reshare.NewOperators, reshareMsg.SignedReshare.Reshare.NewOperators, len(reshareMsg.SignedReshare.Reshare.NewOperators)); err != nil {
		return nil, err
	}
	for id := range dkgResult {
		c.Logger.Info("DKG Reshare results", zap.Any("id", id))
	}
	err = verifyMessageSignatures(id, kyberMsgs, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator dkg results signatures")
	var finalResults [][]byte
	for _, res := range dkgResult {
		finalResults = append(finalResults, res)
	}
	return finalResults, nil
}

// StartDKG starts DKG ceremony at initiator with requested parameters
func (c *Initiator) StartDKG(id [24]byte, withdraw []byte, ids []uint64, network eth2_key_manager_core.Network, owner common.Address, nonce uint64) (*wire.DepositDataCLI, *wire.KeySharesCLI, []*wire.SignedProof, error) {
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
	return c.CreateCeremonyResults(dkgResultsBytes, id, init.Operators, init.WithdrawalCredentials, nil, init.Fork, init.Owner, init.Nonce)
}

func (c *Initiator) StartResigning(id [24]byte, ids []uint64, proofs []*spec.SignedProof, sk *ecdsa.PrivateKey, network eth2_key_manager_core.Network, withdraw []byte, owner [20]byte, nonce uint64) (*wire.DepositDataCLI, *wire.KeySharesCLI, []*wire.SignedProof, error) {
	if len(proofs) == 0 {
		return nil, nil, nil, fmt.Errorf("🤖 unmarshaled proofs object is empty")
	}
	ops, err := ValidatedOperatorData(ids, c.Operators)
	if err != nil {
		return nil, nil, nil, err
	}
	// validate proofs
	for i, op := range ops {
		if err := spec.ValidateCeremonyProof(owner, proofs[0].Proof.ValidatorPubKey, op, *proofs[i]); err != nil {
			return nil, nil, nil, err
		}
	}
	// Construct resign message
	rMsg, err := c.ConstructResignMessage(
		ids,
		proofs[0].Proof.ValidatorPubKey,
		network,
		withdraw,
		owner,
		nonce,
		sk,
		proofs)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("🚀 Starting resign dkg ceremony", zap.Uint64s("operator IDs", ids))
	c.Logger.Info("Outgoing resign request fields",
		zap.String("network", hex.EncodeToString(rMsg.SignedResign.Resign.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(rMsg.SignedResign.Resign.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(rMsg.SignedResign.Resign.Owner[:])),
		zap.Uint64("nonce", rMsg.SignedResign.Resign.Nonce),
		zap.Any("operators IDs", rMsg.Operators))
	for _, proof := range rMsg.Proofs {
		c.Logger.Info("Loaded proof",
			zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
			zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
			zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
			zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
			zap.String("Signature", hex.EncodeToString(proof.Signature)))
	}
	resultsBytes, err := c.ResignMessageFlowHandling(
		rMsg,
		id,
		rMsg.Operators)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.CreateCeremonyResults(resultsBytes, id, rMsg.Operators, rMsg.SignedResign.Resign.WithdrawalCredentials, rMsg.SignedResign.Resign.ValidatorPubKey, rMsg.SignedResign.Resign.Fork, rMsg.SignedResign.Resign.Owner, rMsg.SignedResign.Resign.Nonce)
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
) (*wire.DepositDataCLI, *wire.KeySharesCLI, []*wire.SignedProof, error) {
	dkgResults, err := parseDKGResultsFromBytes(resultsBytes, id)
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
			id,
			dkgResults)
		if err != nil {
			return nil, nil, nil, err
		}
	}
	depositDataJson, keyshares, err := c.processDKGResultResponse(dkgResults, id, ops, withdrawalCredentials, fork, ownerAddress, nonce)
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
		proofsArray = append(proofsArray, &wire.SignedProof{res.SignedProof}) //nolint:all
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

func (c *Initiator) StartResharing(id [24]byte, oldOperatorIDs, newOperatorIDs []uint64, proofs []*spec.SignedProof, sk *ecdsa.PrivateKey, network eth2_key_manager_core.Network, withdraw []byte, owner [20]byte, nonce uint64) (*wire.DepositDataCLI, *wire.KeySharesCLI, []*wire.SignedProof, error) {
	if len(proofs) == 0 {
		return nil, nil, nil, fmt.Errorf("🤖 proofs are empty")
	}
	oldOps, err := ValidatedOperatorData(oldOperatorIDs, c.Operators)
	if err != nil {
		return nil, nil, nil, err
	}
	_, err = ValidatedOperatorData(newOperatorIDs, c.Operators)
	if err != nil {
		return nil, nil, nil, err
	}
	// validate proofs
	for i, op := range oldOps {
		if err := spec.ValidateCeremonyProof(owner, proofs[0].Proof.ValidatorPubKey, op, *proofs[i]); err != nil {
			return nil, nil, nil, err
		}
	}
	// Consruct reshare message
	reshareMsg, err := c.ConstructReshareMessage(
		oldOperatorIDs,
		newOperatorIDs,
		proofs[0].Proof.ValidatorPubKey,
		network,
		withdraw,
		owner,
		nonce,
		sk,
		proofs)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("🚀 Starting resharing ceremony", zap.Uint64s("old operator IDs", oldOperatorIDs), zap.Uint64s("new operator IDs", newOperatorIDs))
	c.Logger.Info("Outgoing reshare request fields",
		zap.Any("Old operator IDs", oldOperatorIDs),
		zap.Any("New operator IDs", newOperatorIDs),
		zap.String("ValidatorPubKey", hex.EncodeToString(reshareMsg.Proofs[0].Proof.ValidatorPubKey)),
		zap.String("network", hex.EncodeToString(reshareMsg.SignedReshare.Reshare.Fork[:])),
		zap.String("withdrawal", hex.EncodeToString(reshareMsg.SignedReshare.Reshare.WithdrawalCredentials)),
		zap.String("owner", hex.EncodeToString(reshareMsg.SignedReshare.Reshare.Owner[:])),
		zap.Uint64("nonce", reshareMsg.SignedReshare.Reshare.Nonce),
		zap.String("EIP1271 owner signature", hex.EncodeToString(reshareMsg.SignedReshare.Signature)))
	for _, proof := range reshareMsg.Proofs {
		c.Logger.Info("Loaded proof",
			zap.String("ValidatorPubKey", hex.EncodeToString(proof.Proof.ValidatorPubKey)),
			zap.String("Owner", hex.EncodeToString(proof.Proof.Owner[:])),
			zap.String("SharePubKey", hex.EncodeToString(proof.Proof.SharePubKey)),
			zap.String("EncryptedShare", hex.EncodeToString(proof.Proof.EncryptedShare)),
			zap.String("Signature", hex.EncodeToString(proof.Signature)))
	}
	resultsBytes, err := c.messageFlowHandlingReshare(id, reshareMsg)
	if err != nil {
		return nil, nil, nil, err
	}
	return c.CreateCeremonyResults(resultsBytes, id, reshareMsg.SignedReshare.Reshare.NewOperators, reshareMsg.SignedReshare.Reshare.WithdrawalCredentials, reshareMsg.SignedReshare.Reshare.ValidatorPubKey, reshareMsg.SignedReshare.Reshare.Fork, reshareMsg.SignedReshare.Reshare.Owner, reshareMsg.SignedReshare.Reshare.Nonce)
}

// processDKGResultResponseInitial deserializes incoming DKG result messages from operators after successful initiation ceremony
func (c *Initiator) processDKGResultResponse(dkgResults []*spec.Result,
	requestID [24]byte,
	ops []*spec.Operator,
	withdrawalCredentials []byte,
	fork [4]byte,
	ownerAddress [20]byte,
	nonce uint64) (*wire.DepositDataCLI, *wire.KeySharesCLI, error) {
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
	_, depositData, masterSigOwnerNonce, err := spec.ValidateResults(ops, withdrawalCredentials, validatorPK, fork, ownerAddress, nonce, requestID, dkgResults)
	if err != nil {
		return nil, nil, err
	}
	network, err := spec_crypto.GetNetworkByFork(fork)
	if err != nil {
		return nil, nil, err
	}
	depositDataJson, err := crypto.BuildDepositDataCLI(network, depositData, wire.DepositCliVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create deposit data json: %v", err)
	}
	c.Logger.Info("✅ deposit data was successfully reconstructed")
	keyshares, err := c.generateSSVKeysharesPayload(ops, dkgResults, masterSigOwnerNonce, ownerAddress, nonce)
	if err != nil {
		return nil, nil, err
	}
	return depositDataJson, keyshares, nil
}

func parseDKGResultsFromBytes(responseResult [][]byte, id [24]byte) (dkgResults []*spec.Result, finalErr error) {
	for i := 0; i < len(responseResult); i++ {
		msg := responseResult[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		if tsp.Message.Type == wire.ErrorMessageType {
			finalErr = errors.Join(finalErr, fmt.Errorf("%s", string(tsp.Message.Data)))
			continue
		}
		if tsp.Message.Type != wire.OutputMessageType {
			finalErr = errors.Join(finalErr, fmt.Errorf("wrong DKG result message type: exp %s, got %s ", wire.OutputMessageType.String(), tsp.Message.Type.String()))
			continue
		}
		result := &spec.Result{}
		if err := result.UnmarshalSSZ(tsp.Message.Data); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		if !bytes.Equal(result.RequestID[:], id[:]) {
			finalErr = errors.Join(finalErr, fmt.Errorf("DKG result has wrong ID, sender ID: %d, message type: %s", tsp.Signer, tsp.Message.Type.String()))
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
func (c *Initiator) SendInitMsg(id [24]byte, init *spec.Init, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error, error) {
	signedInitMsgBts, err := c.prepareAndSignMessage(init, wire.InitMessageType, id, c.Version)
	if err != nil {
		return nil, nil, err
	}
	results, errs := c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, operators)
	return results, errs, nil
}

func (c *Initiator) SendResignMsg(id [24]byte, resign *wire.ResignMessage, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error, error) {
	signedResignMsgBts, err := c.prepareAndSignMessage(resign, wire.ResignMessageType, id, c.Version)
	if err != nil {
		return nil, nil, err
	}
	results, errs := c.SendToAll(consts.API_RESIGN_URL, signedResignMsgBts, operators)
	return results, errs, nil
}

func (c *Initiator) SendReshareMsg(id [24]byte, reshare *wire.ReshareMessage, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error, error) {
	signedReshareMsgBts, err := c.prepareAndSignMessage(reshare, wire.ReshareMessageType, id, c.Version)
	if err != nil {
		return nil, nil, err
	}
	results, errs := c.SendToAll(consts.API_RESHARE_URL, signedReshareMsgBts, operators)
	return results, errs, nil
}

// SendExchangeMsgs sends combined exchange messages to each operator participating in DKG ceremony
func (c *Initiator) SendExchangeMsgs(id [24]byte, exchangeMsgs map[uint64][]byte, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error, error) {
	mltpl, err := makeMultipleSignedTransports(c.PrivateKey, id, exchangeMsgs)
	if err != nil {
		return nil, nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}
	results, errs := c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
	return results, errs, nil
}

func (c *Initiator) SendExchangeMsgsReshare(id [24]byte, exchangeMsgs map[uint64][]byte, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error, error) {
	mltpl, err := makeMultipleSignedTransports(c.PrivateKey, id, exchangeMsgs)
	if err != nil {
		return nil, nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}
	results, errs := c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
	return results, errs, nil
}

// SendKyberMsgs sends combined kyber messages to each operator participating in DKG ceremony
func (c *Initiator) SendKyberMsgs(id [24]byte, kyberDeals map[uint64][]byte, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error, error) {
	mltpl2, err := makeMultipleSignedTransports(c.PrivateKey, id, kyberDeals)
	if err != nil {
		return nil, nil, err
	}
	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return nil, nil, err
	}
	results, errs := c.SendToAll(consts.API_DKG_URL, mltpl2byts, operators)
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
			c.Logger.Error("😥 Operator not healthy: ", zap.Error(err), zap.String("IP", res.IP))
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
		errmsg, parseErr := wire.ParseAsError(res.Result)
		if parseErr == nil {
			return fmt.Errorf("operator returned err: %v", errmsg)
		}
		return err
	}
	// Validate that incoming message is an pong message
	if signedPongMsg.Message.Type != wire.PongMessageType {
		return fmt.Errorf("wrong incoming message type from operator")
	}
	pong := &wire.Pong{}
	if err := pong.UnmarshalSSZ(signedPongMsg.Message.Data); err != nil {
		return err
	}
	pongBytes, err := signedPongMsg.Message.MarshalSSZ()
	if err != nil {
		return err
	}
	pub, err := spec_crypto.ParseRSAPublicKey(pong.PubKey)
	if err != nil {
		return err
	}
	if err := spec_crypto.VerifyRSA(pub, pongBytes, signedPongMsg.Signature); err != nil {
		return err
	}
	c.Logger.Info("🍎 operator online and healthy", zap.Uint64("ID", pong.ID), zap.String("IP", res.IP), zap.String("Version", string(signedPongMsg.Message.Version)), zap.String("Public key", string(pong.PubKey)))
	return nil
}

func (c *Initiator) ConstructReshareMessage(oldOperatorIDs, newOperatorIDs []uint64, validatorPub []byte, ethnetwork e2m_core.Network, withdrawCreds []byte, owner common.Address, nonce uint64, sk *ecdsa.PrivateKey, proofsData []*spec.SignedProof) (*wire.ReshareMessage, error) {
	// Construct reshare message
	oldOps, err := ValidatedOperatorData(oldOperatorIDs, c.Operators)
	if err != nil {
		return nil, err
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
	}
	hash, err := reshare.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	// Sign message root
	ownerSig, err := eth_crypto.Sign(hash[:], sk)
	if err != nil {
		return nil, err
	}
	return &wire.ReshareMessage{
		SignedReshare: &spec.SignedReshare{
			Reshare:   *reshare,
			Signature: ownerSig,
		},
		Proofs: proofsData,
	}, nil
}

func (c *Initiator) ConstructResignMessage(operatorIDs []uint64, validatorPub []byte, ethnetwork e2m_core.Network, withdrawCreds []byte, owner common.Address, nonce uint64, sk *ecdsa.PrivateKey, proofsData []*spec.SignedProof) (*wire.ResignMessage, error) {
	// create resign message
	ops, err := ValidatedOperatorData(operatorIDs, c.Operators)
	if err != nil {
		return nil, err
	}
	resign := spec.Resign{ValidatorPubKey: validatorPub,
		Fork:                  ethnetwork.GenesisForkVersion(),
		WithdrawalCredentials: withdrawCreds,
		Owner:                 owner,
		Nonce:                 nonce}
	hash, err := resign.HashTreeRoot()
	if err != nil {
		return nil, err
	}
	// Sign message root
	ownerSig, err := eth_crypto.Sign(hash[:], sk)
	if err != nil {
		return nil, err
	}
	return &wire.ResignMessage{
		Operators:    ops,
		SignedResign: &spec.SignedResign{Resign: resign, Signature: ownerSig},
		Proofs:       proofsData,
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
