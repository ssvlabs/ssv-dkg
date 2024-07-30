package initiator

import (
	"bytes"
	"context"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/url"
	"sort"
	"strings"
	"time"

	eth2clienthttp "github.com/attestantio/go-eth2-client/http"
	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"
	"go.uber.org/zap"

	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/consts"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
)

// Operator structure represents operators info which is public
type Operator struct {
	Addr   string         // ip:port
	ID     uint64         // operators ID
	PubKey *rsa.PublicKey // operators RSA public key
}

// OperatorDataJson is used to store operators info ar JSON
type OperatorDataJson struct {
	Addr   string `json:"ip"`
	ID     uint64 `json:"id"`
	PubKey string `json:"public_key"`
}

// Operators mapping storage for operator structs [ID]operator
type Operators map[uint64]Operator

func (o Operators) Clone() Operators {
	clone := make(Operators)
	for k, v := range o {
		clone[k] = v
	}
	return clone
}

// Initiator main structure for initiator
type Initiator struct {
	Logger     *zap.Logger                            // logger
	Client     *req.Client                            // http client
	Operators  Operators                              // operators info mapping
	VerifyFunc func(id uint64, msg, sig []byte) error // function to verify signatures of incoming messages
	PrivateKey *rsa.PrivateKey                        // a unique initiator's RSA private key used for signing messages and identity
	Version    []byte
}

// DepositDataJson structure to create a resulting deposit data JSON file according to ETH2 protocol
type DepositDataJson struct {
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

// KeyShares structure to create an json file for ssv smart contract
type KeyShares struct {
	Version   string    `json:"version"`
	CreatedAt time.Time `json:"createdAt"`
	Shares    []Data    `json:"shares"`
}

// Data structure as a part of KeyShares representing BLS validator public key and information about validators
type Data struct {
	ShareData `json:"data"`
	Payload   Payload `json:"payload"`
}

type ShareData struct {
	OwnerNonce   uint64         `json:"ownerNonce"`
	OwnerAddress string         `json:"ownerAddress "`
	PublicKey    string         `json:"publicKey"`
	Operators    []OperatorData `json:"operators"`
}

// OperatorData structure to represent information about operators participating in signing validator's duty
type OperatorData struct {
	ID          uint64 `json:"id"`
	OperatorKey string `json:"operatorKey"` // encoded RSA public key
}

type Payload struct {
	PublicKey   string   `json:"publicKey"`   // validator's public key
	OperatorIDs []uint64 `json:"operatorIds"` // operators IDs
	SharesData  string   `json:"sharesData"`  // encrypted private BLS shares of each operator participating in DKG
}

type pongResult struct {
	ip     string
	err    error
	result []byte
}

type CeremonySigs struct {
	ValidatorPubKey    string   `json:"validator"`
	OperatorIDs        []uint64 `json:"operatorIds"`
	Sigs               string   `json:"ceremonySigs"`
	InitiatorPublicKey string   `json:"initiatorPublicKey"`
}

// GeneratePayload generates at initiator ssv smart contract payload using DKG result  received from operators participating in DKG ceremony
func GeneratePayload(result []dkg.Result, sigOwnerNonce []byte, owner common.Address, nonce uint64) (*KeyShares, error) {
	// check results sorted by operatorID
	sorted := sort.SliceIsSorted(result, func(p, q int) bool {
		return result[p].OperatorID < result[q].OperatorID
	})
	if !sorted {
		return nil, fmt.Errorf("fail to sort result slice by operator ID")
	}
	operatorData := make([]OperatorData, 0)
	operatorIds := make([]uint64, 0)

	var pubkeys []byte
	var encryptedShares []byte
	for i := 0; i < len(result); i++ {
		// Data for forming share string
		pubkeys = append(pubkeys, result[i].SharePubKey...)
		encryptedShares = append(encryptedShares, result[i].EncryptedShare...)

		encPubKey, err := crypto.EncodePublicKey(result[i].PubKeyRSA)
		if err != nil {
			return nil, err
		}
		operatorData = append(operatorData, OperatorData{
			ID:          result[i].OperatorID,
			OperatorKey: string(encPubKey),
		})
		operatorIds = append(operatorIds, result[i].OperatorID)
	}

	// Create share string for ssv contract
	pubkeys = append(pubkeys, encryptedShares...)
	sigOwnerNonce = append(sigOwnerNonce, pubkeys...)

	operatorCount := len(result)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset

	if sharesExpectedLength != len(sigOwnerNonce) {
		return nil, fmt.Errorf("malformed ssv share data")
	}

	data := []Data{{ShareData{
		OwnerNonce:   nonce,
		OwnerAddress: owner.Hex(),
		PublicKey:    "0x" + hex.EncodeToString(result[0].ValidatorPubKey),
		Operators:    operatorData,
	}, Payload{
		PublicKey:   "0x" + hex.EncodeToString(result[0].ValidatorPubKey),
		OperatorIDs: operatorIds,
		SharesData:  "0x" + hex.EncodeToString(sigOwnerNonce),
	}}}

	ks := &KeyShares{}
	ks.Version = "v1.1.0"
	ks.Shares = data
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

func GenerateAggregatesKeyshares(keySharesArr []*KeyShares) (*KeyShares, error) {
	// order the keyshares by nonce
	sort.SliceStable(keySharesArr, func(i, j int) bool {
		return keySharesArr[i].Shares[0].OwnerNonce < keySharesArr[j].Shares[0].OwnerNonce
	})
	sorted := sort.SliceIsSorted(keySharesArr, func(p, q int) bool {
		return keySharesArr[p].Shares[0].OwnerNonce < keySharesArr[q].Shares[0].OwnerNonce
	})
	if !sorted {
		return nil, fmt.Errorf("slice is not sorted")
	}
	var data []Data
	for _, keyShares := range keySharesArr {
		data = append(data, keyShares.Shares...)
	}
	ks := &KeyShares{}
	ks.Version = "v1.1.0"
	ks.Shares = data
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

// New creates a main initiator structure
func New(privKey *rsa.PrivateKey, operatorMap Operators, logger *zap.Logger, ver string) *Initiator {
	client := req.C()
	// Set timeout for operator responses
	client.SetTimeout(30 * time.Second)
	c := &Initiator{
		Logger:     logger,
		Client:     client,
		Operators:  operatorMap,
		PrivateKey: privKey,
		VerifyFunc: CreateVerifyFunc(operatorMap),
		Version:    []byte(ver),
	}
	return c
}

// opReqResult structure to represent http communication messages incoming to initiator from operators
type opReqResult struct {
	operatorID uint64
	err        error
	result     []byte
}

// SendAndCollect ssends http message to operator and read the response
func (c *Initiator) SendAndCollect(op Operator, method string, data []byte) ([]byte, error) {
	r := c.Client.R()
	r.SetBodyBytes(data)
	res, err := r.Post(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}
	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Logger.Debug("operator responded", zap.Uint64("operator", op.ID), zap.String("method", method))
	return resdata, nil
}

// GetAndCollect request Get at operator route
func (c *Initiator) GetAndCollect(op Operator, method string) ([]byte, error) {
	r := c.Client.R()
	res, err := r.Get(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}
	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Logger.Debug("operator responded", zap.String("IP", op.Addr), zap.String("method", method))
	return resdata, nil
}

// SendToAll sends http messages to all operators. Makes sure that all responses are received
func (c *Initiator) SendToAll(method string, msg []byte, operatorsIDs []*wire.Operator) ([][]byte, error) {
	resc := make(chan opReqResult, len(operatorsIDs))
	for _, op := range operatorsIDs {
		go func(operator Operator) {
			res, err := c.SendAndCollect(operator, method, msg)
			resc <- opReqResult{
				operatorID: operator.ID,
				err:        err,
				result:     res,
			}
		}(c.Operators[op.ID])
	}
	final := make([][]byte, 0, len(operatorsIDs))

	errarr := make([]error, 0)

	for i := 0; i < len(operatorsIDs); i++ {
		res := <-resc
		if res.err != nil {
			errarr = append(errarr, fmt.Errorf("operator ID: %d, %w", res.operatorID, res.err))
			continue
		}
		final = append(final, res.result)
	}

	finalerr := error(nil)

	if len(errarr) > 0 {
		finalerr = errors.Join(errarr...)
	}

	return final, finalerr
}

// parseAsError parses the error from an operator
func ParseAsError(msg []byte) (parsedErr, err error) {
	sszerr := &wire.ErrSSZ{}
	err = sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, err
	}
	return errors.New(string(sszerr.Error)), nil
}

// VerifyAll verifies incoming to initiator messages from operators.
// Incoming message from operator should have same DKG ceremony ID and a valid signature
func (c *Initiator) VerifyAll(id [24]byte, allmsgs [][]byte) error {
	var errs error
	for i := 0; i < len(allmsgs); i++ {
		msg := allmsgs[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := ParseAsError(msg)
			if parseErr == nil {
				errs = errors.Join(errs, fmt.Errorf("%v", errmsg))
				continue
			}
			return err
		}
		signedBytes, err := tsp.Message.MarshalSSZ()
		if err != nil {
			return err
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return fmt.Errorf("incoming message has wrong ID, aborting... operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		// Verification operator signatures
		if err := c.VerifyFunc(tsp.Signer, signedBytes, tsp.Signature); err != nil {
			return err
		}
	}
	return errs
}

// MakeMultiple creates a one combined message from operators with initiator signature
func (c *Initiator) MakeMultiple(id [24]byte, allmsgs [][]byte) (*wire.MultipleSignedTransports, error) {
	// We are collecting responses at SendToAll which gives us int(msg)==int(oprators)
	final := &wire.MultipleSignedTransports{
		Identifier: id,
		Messages:   make([]*wire.SignedTransport, len(allmsgs)),
	}
	var allMsgsBytes []byte
	for i := 0; i < len(allmsgs); i++ {
		msg := allmsgs[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := ParseAsError(msg)
			if parseErr == nil {
				return nil, fmt.Errorf("msg %d returned: %v", i, errmsg)
			}
			return nil, err
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return nil, fmt.Errorf("incoming message has wrong ID, aborting... operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		final.Messages[i] = tsp
		allMsgsBytes = append(allMsgsBytes, msg...)
	}
	// sign message by initiator
	c.Logger.Debug("Signing combined messages from operators", zap.String("initiator_id", hex.EncodeToString(c.PrivateKey.N.Bytes())))
	sig, err := crypto.SignRSA(c.PrivateKey, allMsgsBytes)
	if err != nil {
		return nil, err
	}
	final.Signature = sig
	return final, nil
}

// ValidatedOperatorData validates operators information data before starting a DKG ceremony
func ValidatedOperatorData(ids []uint64, operators Operators) ([]*wire.Operator, error) {
	if len(ids) < 4 {
		return nil, fmt.Errorf("wrong operators len: < 4")
	}
	if len(ids) > 13 {
		return nil, fmt.Errorf("wrong operators len: > 13")
	}
	if len(ids)%3 != 1 {
		return nil, fmt.Errorf("amount of operators should be 4,7,10,13")
	}

	ops := make([]*wire.Operator, 0)
	opMap := make(map[uint64]struct{})
	for _, id := range ids {
		op, ok := operators[id]
		if !ok {
			return nil, errors.New("operator is not in given operator data list")
		}

		_, exist := opMap[id]
		if exist {
			return nil, errors.New("operators ids should be unique in the list")
		}
		opMap[id] = struct{}{}

		pkBytes, err := crypto.EncodePublicKey(op.PubKey)
		if err != nil {
			return nil, fmt.Errorf("can't encode public key err: %v", err)
		}
		ops = append(ops, &wire.Operator{
			ID:     op.ID,
			PubKey: pkBytes,
		})
	}
	return ops, nil
}

// messageFlowHandling main steps of DKG at initiator
func (c *Initiator) messageFlowHandling(init *wire.Init, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	c.Logger.Info("phase 1: sending init message to operators")
	results, err := c.SendInitMsg(init, id, operators)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(id, results)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 1: ✅ verified operator init responses signatures")

	c.Logger.Info("phase 2: ➡️ sending operator data (exchange messages) required for dkg")
	results, err = c.SendExchangeMsgs(results, id, operators)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(id, results)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator responses (deal messages) signatures")
	c.Logger.Info("phase 3: ➡️ sending deal dkg data to all operators")
	dkgResult, err := c.SendKyberMsgs(results, id, operators)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(id, results)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator dkg results signatures")
	return dkgResult, nil
}

func (c *Initiator) messageFlowHandlingReshare(reshare *wire.Reshare, newID [24]byte, oldOperators, newOperators []*wire.Operator) ([][]byte, error) {
	c.Logger.Info("phase 1: sending reshare message to old operators")
	allOps := utils.JoinSets(oldOperators, newOperators)
	results, err := c.SendReshareMsg(reshare, newID, allOps)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(newID, results)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 1: ✅ verified operator resharing responses signatures")
	c.Logger.Info("phase 2: ➡️ sending operator data (exchange messages) required for dkg")
	results, err = c.SendExchangeMsgs(results, newID, allOps)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(newID, results)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified old operator responses (deal messages) signatures")
	c.Logger.Info("phase 3: ➡️ sending deal dkg data to new operators")

	dkgResult, err := c.SendKyberMsgs(results, newID, newOperators)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(newID, results)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator dkg results signatures")
	return dkgResult, nil
}

func (c *Initiator) messageFlowHandlingResign(resign *wire.ReSign, newID [24]byte, oldOperators []*wire.Operator, t int) ([][]byte, error) {
	results, err := c.SendReSignMsg(resign, newID, oldOperators, t)
	if err != nil {
		return nil, err
	}
	err = c.VerifyAll(newID, results)
	if err != nil {
		return nil, err
	}
	return results, nil
}

// reconstructAndVerifyDepositData verifies incoming from operators DKG result data and creates a resulting DepositDataJson structure to store as JSON file
func (c *Initiator) reconstructAndVerifyDepositData(ids []uint64, withdrawCredentials []byte, validatorPubKey *bls.PublicKey, network eth2_key_manager_core.Network, sigDepositShares []*bls.Sign, sharePks []*bls.PublicKey) (*DepositDataJson, error) {
	shareRoot, err := crypto.DepositDataRoot(withdrawCredentials, validatorPubKey, network, dkg.MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit data root: %v", err)
	}
	// Verify partial signatures and recovered threshold signature
	err = crypto.VerifyPartialSigs(sigDepositShares, sharePks, shareRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to verify partial signatures: %v", err)
	}

	// Recover and verify Master Signature
	// 1. Recover validator pub key
	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(ids, sharePks)
	if err != nil {
		return nil, fmt.Errorf("failed to recover validator public key from shares: %v", err)
	}

	if !bytes.Equal(validatorPubKey.Serialize(), validatorRecoveredPK.Serialize()) {
		return nil, fmt.Errorf("incoming validator pub key is not equal recovered from shares: want %x, got %x", validatorRecoveredPK.Serialize(), validatorPubKey.Serialize())
	}
	// 2. Recover master signature from shares
	reconstructedDepositMasterSig, err := crypto.RecoverMasterSig(ids, sigDepositShares)
	if err != nil {
		return nil, fmt.Errorf("failed to recover master signature from shares: %v", err)
	}
	if !reconstructedDepositMasterSig.VerifyByte(validatorPubKey, shareRoot) {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}

	depositData, root, err := crypto.DepositData(reconstructedDepositMasterSig.Serialize(), withdrawCredentials, validatorPubKey.Serialize(), network, dkg.MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit data: %v", err)
	}
	// Verify deposit data
	depositVerRes, err := crypto.VerifyDepositData(depositData, network)
	if err != nil {
		return nil, fmt.Errorf("failed to verify deposit data: %v", err)
	}
	if !depositVerRes {
		return nil, fmt.Errorf("deposit data is invalid")
	}
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                dkg.MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, err := depositMsg.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to compute deposit message root: %v", err)
	}
	// Final checks of prepared deposit data
	if !bytes.Equal(depositData.PublicKey[:], validatorRecoveredPK.Serialize()) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong validator public key %x", depositData.PublicKey[:])
	}
	if !bytes.Equal(depositData.WithdrawalCredentials, crypto.ETH1WithdrawalCredentialsHash(withdrawCredentials)) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong withdrawal address %x", depositData.WithdrawalCredentials)
	}
	if !(dkg.MaxEffectiveBalanceInGwei == depositData.Amount) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong amount %d", depositData.Amount)
	}
	forkbytes := network.GenesisForkVersion()
	depositDataJson := &DepositDataJson{
		PubKey:                hex.EncodeToString(validatorPubKey.Serialize()),
		WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
		Amount:                dkg.MaxEffectiveBalanceInGwei,
		Signature:             hex.EncodeToString(reconstructedDepositMasterSig.Serialize()),
		DepositMessageRoot:    hex.EncodeToString(depositMsgRoot[:]),
		DepositDataRoot:       hex.EncodeToString(root[:]),
		ForkVersion:           hex.EncodeToString(forkbytes[:]),
		NetworkName:           string(network),
		DepositCliVersion:     DepositCliVersion,
	}

	return depositDataJson, nil
}

// StartDKG starts DKG ceremony at initiator with requested parameters
func (c *Initiator) StartDKG(id [24]byte, withdraw []byte, ids []uint64, network eth2_key_manager_core.Network, owner common.Address, nonce uint64) (*DepositDataJson, *KeyShares, *CeremonySigs, error) {

	ops, err := ValidatedOperatorData(ids, c.Operators)
	if err != nil {
		return nil, nil, nil, err
	}

	pkBytes, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	instanceIDField := zap.String("instance_id", hex.EncodeToString(id[:]))
	c.Logger.Info("🚀 Starting dkg ceremony", zap.String("initiator_id", string(pkBytes)), zap.Uint64s("operator_ids", ids), instanceIDField)

	// compute threshold (3f+1)
	threshold := len(ids) - ((len(ids) - 1) / 3)
	// make init message
	init := &wire.Init{
		Operators:             ops,
		T:                     uint64(threshold),
		WithdrawalCredentials: withdraw,
		Fork:                  network.GenesisForkVersion(),
		Owner:                 owner,
		Nonce:                 nonce,
		InitiatorPublicKey:    pkBytes,
	}
	c.Logger = c.Logger.With(instanceIDField)

	dkgResultsBytes, err := c.messageFlowHandling(init, id, ops)
	if err != nil {
		return nil, nil, nil, err
	}
	dkgResults, err := parseDKGResultsFromBytes(dkgResultsBytes, id)
	if err != nil {
		return nil, nil, nil, err
	}
	sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, err := c.ProcessDKGResultResponse(dkgResults)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("🏁 DKG completed, verifying deposit data and ssv payload")
	var validatorPubKey bls.PublicKey
	if err := validatorPubKey.Deserialize(dkgResults[0].ValidatorPubKey); err != nil {
		return nil, nil, nil, err
	}
	depositDataJson, err := c.reconstructAndVerifyDepositData(ids, init.WithdrawalCredentials, &validatorPubKey, network, sigDepositShares, sharePks)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ verified deposit data")

	// Verify partial signatures for SSV contract owner+nonce and recovered threshold signature
	data := []byte(fmt.Sprintf("%s:%d", common.Address(init.Owner).String(), init.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))

	err = crypto.VerifyPartialSigs(ssvContractOwnerNonceSigShares, sharePks, hash)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ verified partial signatures from operators")
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig, err := crypto.RecoverMasterSig(ids, ssvContractOwnerNonceSigShares)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ successfully reconstructed master signature from partial signatures (threshold holds)")
	err = crypto.VerifyOwnerNonceSignature(reconstructedOwnerNonceMasterSig.Serialize(), init.Owner, validatorPubKey.Serialize(), uint16(init.Nonce))
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ verified owner and nonce master signature")
	keyshares, err := GeneratePayload(dkgResults, reconstructedOwnerNonceMasterSig.Serialize(), owner, nonce)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ verified master signature for ssv contract data")
	// sending back to operators results
	depositData, err := json.Marshal(depositDataJson)
	if err != nil {
		return nil, nil, nil, err
	}
	keysharesData, err := json.Marshal(keyshares)
	if err != nil {
		return nil, nil, nil, err
	}
	ceremonySigs, err := c.GetCeremonySigs(dkgResults)
	if err != nil {
		return nil, nil, nil, err
	}
	ceremonySigsBytes, err := json.Marshal(ceremonySigs)
	if err != nil {
		return nil, nil, nil, err
	}
	resultMsg := &wire.ResultData{
		Operators:     ops,
		Identifier:    id,
		DepositData:   depositData,
		KeysharesData: keysharesData,
		CeremonySigs:  ceremonySigsBytes,
	}
	err = c.sendResult(resultMsg, ops, consts.API_RESULTS_URL, id)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("🤖 Error storing results at operators %w", err)
	}
	return depositDataJson, keyshares, ceremonySigs, nil
}

func (c *Initiator) StartReshare(id [24]byte, newOpIDs []uint64, keysharesFile, ceremonySigs []byte, nonce uint64) (*KeyShares, *CeremonySigs, error) {
	var ks *KeyShares
	if err := json.Unmarshal(keysharesFile, &ks); err != nil {
		return nil, nil, err
	}
	// var cSigs *CeremonySigs
	// if err := json.Unmarshal(ceremonySigs, &cSigs); err != nil {
	// 	return nil, nil, err
	// }
	// cSigBytes, err := hex.DecodeString(cSigs.Sigs)
	// if err != nil {
	// 	return nil, nil, err
	// }
	oldOpIDs := ks.Shares[0].Payload.OperatorIDs
	owner := common.HexToAddress(ks.Shares[0].OwnerAddress)
	oldOps, err := ValidatedOperatorData(oldOpIDs, c.Operators)
	if err != nil {
		return nil, nil, err
	}
	newOps, err := ValidatedOperatorData(newOpIDs, c.Operators)
	if err != nil {
		return nil, nil, err
	}
	pkBytes, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	instanceIDField := zap.String("instance_id", hex.EncodeToString(id[:]))
	c.Logger.Info("🚀 Starting ReSHARING ceremony", zap.String("initiator_id", string(pkBytes)), zap.Uint64s("old_operator_ids", oldOpIDs), zap.Uint64s("new_operator_ids", newOpIDs), instanceIDField)
	// compute threshold (3f+1)
	oldThreshold := len(oldOpIDs) - ((len(oldOpIDs) - 1) / 3)
	newThreshold := len(newOpIDs) - ((len(newOpIDs) - 1) / 3)
	sharesData, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
	if err != nil {
		return nil, nil, err
	}
	reshare := &wire.Reshare{
		OldOperators: oldOps,
		NewOperators: newOps,
		OldT:         uint64(oldThreshold),
		NewT:         uint64(newThreshold),
		Owner:        owner,
		Nonce:        nonce,
		Keyshares:    sharesData,
		// CeremonySigs:       cSigBytes,
		InitiatorPublicKey: pkBytes,
	}
	dkgResultsBytes, err := c.messageFlowHandlingReshare(reshare, id, oldOps, newOps)
	if err != nil {
		return nil, nil, err
	}
	dkgResults, err := parseDKGResultsFromBytes(dkgResultsBytes, id)
	if err != nil {
		return nil, nil, err
	}
	_, _, ssvContractOwnerNonceSigShares, err := c.ProcessDKGResultResponse(dkgResults)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("🏁 DKG completed, verifying deposit data and ssv payload")
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig, err := crypto.RecoverMasterSig(newOpIDs, ssvContractOwnerNonceSigShares)
	if err != nil {
		return nil, nil, err
	}
	keyshares, err := GeneratePayload(dkgResults, reconstructedOwnerNonceMasterSig.Serialize(), owner, nonce)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("✅ verified master signature for ssv contract data")
	// sending back to operators results
	keysharesData, err := json.Marshal(keyshares)
	if err != nil {
		return nil, nil, err
	}
	ceremonySigsNew, err := c.GetCeremonySigs(dkgResults)
	if err != nil {
		return nil, nil, err
	}
	ceremonySigsNewBytes, err := json.Marshal(ceremonySigsNew)
	if err != nil {
		return nil, nil, err
	}
	resultMsg := &wire.ResultData{
		Operators:     newOps,
		Identifier:    id,
		DepositData:   nil,
		KeysharesData: keysharesData,
		CeremonySigs:  ceremonySigsNewBytes,
	}
	err = c.sendResult(resultMsg, newOps, consts.API_RESULTS_URL, id)
	if err != nil {
		c.Logger.Error("🤖 Error storing results at operators", zap.Error(err))
	}
	return keyshares, ceremonySigsNew, nil
}

func (c *Initiator) StartResigning(id [24]byte, ks *Data, client *eth2clienthttp.Service, ctx context.Context) (*phase0.SignedVoluntaryExit, string, error) {
	oldOpIDs := ks.Payload.OperatorIDs
	oldOps, err := ValidatedOperatorData(oldOpIDs, c.Operators)
	if err != nil {
		return nil, "", err
	}
	pkBytes, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, "", err
	}
	instanceIDField := zap.String("instance_id", hex.EncodeToString(id[:]))
	c.Logger.Info("🚀 Starting ReSigning ceremony", zap.String("initiator_id", string(pkBytes)), zap.Uint64s("old_operator_ids", oldOpIDs), instanceIDField)
	sharesData, err := hex.DecodeString(ks.Payload.SharesData[2:])
	if err != nil {
		return nil, "", err
	}

	epoch, err := client.EpochFromStateID(ctx, "finalized")
	if err != nil {
		return nil, "", fmt.Errorf("failed to get slot from state ID: %w", err)
	}

	validatorPubKey := &bls.PublicKey{}
	if err := validatorPubKey.DeserializeHexStr(ks.Payload.PublicKey[2:]); err != nil {
		return nil, "", fmt.Errorf("failed to deserialize validator public key: %w", err)
	}
	pk := phase0.BLSPubKey(validatorPubKey.Serialize())
	validatorMap, err := client.ValidatorsByPubKey(ctx, "finalized", []phase0.BLSPubKey{pk})
	if err != nil {
		return nil, "", fmt.Errorf("failed to get validator by public key: %w", err)
	}
	var index phase0.ValidatorIndex
	for _, val := range validatorMap {
		if val.Validator.PublicKey.String() == pk.String() {
			index = val.Index
			break
		}
	}
	if index == 0 {
		return nil, "", fmt.Errorf("failed to get validator index from beacon node")
	}
	exitMsg := phase0.VoluntaryExit{
		Epoch:          epoch,
		ValidatorIndex: index,
	}

	genesis, err := client.Genesis(ctx)
	if err != nil {
		return nil, "", err
	}

	forkData := &phase0.ForkData{
		CurrentVersion:        phase0.Version([]byte{0x4, 0x1, 0x70, 0x0}),
		GenesisValidatorsRoot: genesis.GenesisValidatorsRoot,
	}

	root, err := forkData.HashTreeRoot()
	if err != nil {
		return nil, "", err
	}

	var domain phase0.Domain
	copy(domain[:], ssvspec_types.DomainVoluntaryExit[:])
	copy(domain[4:], root[:])

	root, err = ssvspec_types.ComputeETHSigningRoot(&exitMsg, domain)
	if err != nil {
		return nil, "", err
	}
	resignMsg := &wire.ReSign{
		OldOperators: oldOps,
		Keyshares:    sharesData,
		Root:         root[:],
	}
	// compute threshold (3f+1)
	oldThreshold := len(oldOpIDs) - ((len(oldOpIDs) - 1) / 3)
	resignResultsBytes, err := c.messageFlowHandlingResign(resignMsg, id, oldOps, oldThreshold)
	if err != nil {
		return nil, "", err
	}
	resignResults, err := parseResignResultsFromBytes(resignResultsBytes, id)
	if err != nil {
		return nil, "", err
	}
	// verify partial sigs and recover master sig
	var ids []uint64
	var partSigs []*bls.Sign
	for _, r := range resignResults {
		partSig := &bls.Sign{}
		ids = append(ids, r.OperatorID)
		err := partSig.Deserialize(r.RootPartialSig)
		if err != nil {
			return nil, "", err
		}
		partSigs = append(partSigs, partSig)
	}
	masterSig, err := crypto.RecoverMasterSig(ids, partSigs)
	if err != nil {
		return nil, "", err
	}
	if !masterSig.VerifyByte(validatorPubKey, root[:]) {
		return nil, "", fmt.Errorf("deposit root signature recovered from shares is invalid")
	}

	specSig := phase0.BLSSignature{}
	copy(specSig[:], masterSig.Serialize())

	signedVoluntaryExit := &phase0.SignedVoluntaryExit{
		Message:   &exitMsg,
		Signature: specSig,
	}

	return signedVoluntaryExit, ks.Payload.PublicKey, nil
}

type KeySign struct {
	ValidatorPK ssvspec_types.ValidatorPK
	SigningRoot []byte
}

// Encode returns a msg encoded bytes or error
func (msg *KeySign) Encode() ([]byte, error) {
	return json.Marshal(msg)
}

// Decode returns error if decoding failed
func (msg *KeySign) Decode(data []byte) error {
	return json.Unmarshal(data, msg)
}

// CreateVerifyFunc creates function to verify each participating operator RSA signature for incoming to initiator messages
func CreateVerifyFunc(ops Operators) func(id uint64, msg []byte, sig []byte) error {
	inst_ops := make(map[uint64]*rsa.PublicKey)
	for _, op := range ops {
		inst_ops[op.ID] = op.PubKey
	}
	return func(id uint64, msg []byte, sig []byte) error {
		pk, ok := inst_ops[id]
		if !ok {
			return fmt.Errorf("cant find operator, was it provided at operators information file %d", id)
		}
		return crypto.VerifyRSA(pk, msg, sig)
	}
}

// ProcessDKGResultResponse deserializes incoming DKG result messages from operators
func (c *Initiator) ProcessDKGResultResponse(dkgResults []dkg.Result) (sharePks []*bls.PublicKey, sigDepositShares, ssvContractOwnerNonceSigShares []*bls.Sign, err error) {
	// check results sorted by operatorID
	sorted := sort.SliceIsSorted(dkgResults, func(p, q int) bool {
		return dkgResults[p].OperatorID < dkgResults[q].OperatorID
	})
	if !sorted {
		return nil, nil, nil, fmt.Errorf("slice is not sorted")
	}
	for i := 0; i < len(dkgResults); i++ {
		sharePubKey := &bls.PublicKey{}
		if err := sharePubKey.Deserialize(dkgResults[i].SharePubKey); err != nil {
			return nil, nil, nil, err
		}
		sharePks = append(sharePks, sharePubKey)
		depositShareSig := &bls.Sign{}
		if dkgResults[i].DepositPartialSignature != nil {
			if err := depositShareSig.Deserialize(dkgResults[i].DepositPartialSignature); err != nil {
				return nil, nil, nil, err
			}
			sigDepositShares = append(sigDepositShares, depositShareSig)
		}
		ownerNonceShareSig := &bls.Sign{}
		if err := ownerNonceShareSig.Deserialize(dkgResults[i].OwnerNoncePartialSignature); err != nil {
			return nil, nil, nil, err
		}
		ssvContractOwnerNonceSigShares = append(ssvContractOwnerNonceSigShares, ownerNonceShareSig)
		c.Logger.Debug("Received DKG result from operator", zap.Uint64("ID", dkgResults[i].OperatorID))
	}
	return sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, nil
}

func parseDKGResultsFromBytes(responseResult [][]byte, id [24]byte) (dkgResults []dkg.Result, finalErr error) {
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
		result := dkg.Result{}
		if err := result.Decode(tsp.Message.Data); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		if !bytes.Equal(result.RequestID[:], id[:]) {
			finalErr = errors.Join(finalErr, fmt.Errorf("DKG result has wrong ID "))
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
	return dkgResults, nil
}

func parseResignResultsFromBytes(responseResult [][]byte, id [24]byte) (resignResults []wire.ReSignResult, finalErr error) {
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
		if tsp.Message.Type != wire.ResignResultMessageType {
			finalErr = errors.Join(finalErr, fmt.Errorf("wrong DKG result message type: exp %s, got %s ", wire.OutputMessageType.String(), tsp.Message.Type.String()))
			continue
		}
		result := wire.ReSignResult{}
		if err := result.UnmarshalJSON(tsp.Message.Data); err != nil {
			finalErr = errors.Join(finalErr, err)
			continue
		}
		resignResults = append(resignResults, result)
	}
	if finalErr != nil {
		return nil, finalErr
	}
	// sort the results by operatorID
	sort.SliceStable(resignResults, func(i, j int) bool {
		return resignResults[i].OperatorID < resignResults[j].OperatorID
	})
	return resignResults, nil
}

// SendInitMsg sends initial DKG ceremony message to participating operators from initiator
func (c *Initiator) SendInitMsg(init *wire.Init, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	signedInitMsgBts, err := c.prepareAndSignMessage(init, wire.InitMessageType, id, c.Version)
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, operators)
}

func (c *Initiator) SendReshareMsg(reshare *wire.Reshare, id [24]byte, ops []*wire.Operator) ([][]byte, error) {
	signedReshareMsgBts, err := c.prepareAndSignMessage(reshare, wire.ReshareMessageType, id, c.Version)
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_RESHARE_URL, signedReshareMsgBts, ops)
}

func (c *Initiator) SendReSignMsg(resign *wire.ReSign, id [24]byte, ops []*wire.Operator, t int) ([][]byte, error) {
	signedReSignMsgBts, err := c.prepareAndSignMessage(resign, wire.ResignMessageType, id, c.Version)
	if err != nil {
		return nil, err
	}
	res, err := c.SendToAll(consts.API_RESIGN_URL, signedReSignMsgBts, ops)
	if len(res) < t {
		return nil, fmt.Errorf("Operator successful replies less than threshold, cant continue: %w", err)
	}
	return res, nil
}

// SendExchangeMsgs sends combined exchange messages to each operator participating in DKG ceremony
func (c *Initiator) SendExchangeMsgs(exchangeMsgs [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	mltpl, err := c.MakeMultiple(id, exchangeMsgs)
	if err != nil {
		return nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
}

// SendKyberMsgs sends combined kyber messages to each operator participating in DKG ceremony
func (c *Initiator) SendKyberMsgs(kyberDeals [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	mltpl2, err := c.MakeMultiple(id, kyberDeals)
	if err != nil {
		return nil, err
	}

	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_DKG_URL, mltpl2byts, operators)
}

func (c *Initiator) SendPingMsg(ping *wire.Ping, operators []*wire.Operator) ([][]byte, error) {
	signedPingMsgBts, err := c.prepareAndSignMessage(ping, wire.PingMessageType, [24]byte{}, c.Version)
	if err != nil {
		return nil, err
	}
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_HEALTH_CHECK_URL, signedPingMsgBts, operators)
}

func (c *Initiator) sendResult(resData *wire.ResultData, operators []*wire.Operator, method string, id [24]byte) error {
	signedMsgBts, err := c.prepareAndSignMessage(resData, wire.ResultMessageType, id, c.Version)
	if err != nil {
		return err
	}
	_, err = c.SendToAll(method, signedMsgBts, operators)
	if err != nil {
		return err
	}
	return nil
}

// LoadOperatorsJson deserialize operators data from JSON
func LoadOperatorsJson(operatorsMetaData []byte) (Operators, error) {
	opmap := make(map[uint64]Operator)
	var operators []OperatorDataJson
	err := json.Unmarshal(bytes.TrimSpace(operatorsMetaData), &operators)
	if err != nil {
		return nil, err
	}
	for _, opdata := range operators {
		_, err := url.ParseRequestURI(opdata.Addr)
		if err != nil {
			return nil, fmt.Errorf("invalid operator URL %s", err.Error())
		}
		operatorKeyByte, err := base64.StdEncoding.DecodeString(opdata.PubKey)
		if err != nil {
			return nil, err
		}
		pemBlock, _ := pem.Decode(operatorKeyByte)
		if pemBlock == nil {
			return nil, errors.New("decode PEM block")
		}
		pbKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		opmap[opdata.ID] = Operator{
			Addr:   strings.TrimRight(opdata.Addr, "/"),
			ID:     opdata.ID,
			PubKey: pbKey.(*rsa.PublicKey),
		}
	}
	return opmap, nil
}

func VerifyDepositData(depsitDataJson *DepositDataJson, withdrawCred []byte, owner common.Address, nonce uint16) error {
	if !bytes.Equal(crypto.ETH1WithdrawalCredentialsHash(withdrawCred), hexutil.MustDecode("0x"+depsitDataJson.WithdrawalCredentials)) {
		return fmt.Errorf("wrong WithdrawalCredentials at result")
	}
	masterSig := &bls.Sign{}
	if err := masterSig.DeserializeHexStr(depsitDataJson.Signature); err != nil {
		return err
	}
	valdatorPubKey := &bls.PublicKey{}
	if err := valdatorPubKey.DeserializeHexStr(depsitDataJson.PubKey); err != nil {
		return err
	}
	// Check root
	var fork [4]byte
	copy(fork[:], hexutil.MustDecode("0x"+depsitDataJson.ForkVersion))
	depositDataRoot, err := crypto.DepositDataRoot(withdrawCred, valdatorPubKey, utils.GetNetworkByFork(fork), dkg.MaxEffectiveBalanceInGwei)
	if err != nil {
		return err
	}
	res := masterSig.VerifyByte(valdatorPubKey, depositDataRoot)
	if !res {
		return fmt.Errorf("wrong master sig at result")
	}
	depositData, _, err := crypto.DepositData(masterSig.Serialize(), withdrawCred, valdatorPubKey.Serialize(), utils.GetNetworkByFork(fork), dkg.MaxEffectiveBalanceInGwei)
	if err != nil {
		return err
	}
	res, err = crypto.VerifyDepositData(depositData, utils.GetNetworkByFork(fork))
	if err != nil {
		return err
	}
	if !res {
		return fmt.Errorf("wrong deposit data")
	}
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                dkg.MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, err := depositMsg.HashTreeRoot()
	if err != nil {
		return fmt.Errorf("failed to compute deposit message root: %v", err)
	}
	if !bytes.Equal(depositMsgRoot[:], hexutil.MustDecode("0x"+depsitDataJson.DepositMessageRoot)) {
		return fmt.Errorf("wrong DepositMessageRoot at result")
	}
	return nil
}

func (c *Initiator) Ping(ips []string) error {
	client := req.C()
	// Set timeout for operator responses
	client.SetTimeout(30 * time.Second)
	resc := make(chan pongResult, len(ips))
	for _, ip := range ips {
		go func(ip string) {
			resdata, err := c.GetAndCollect(Operator{Addr: ip}, consts.API_HEALTH_CHECK_URL)
			resc <- pongResult{
				ip:     ip,
				err:    err,
				result: resdata,
			}
		}(ip)
	}
	for i := 0; i < len(ips); i++ {
		res := <-resc
		err := c.processPongMessage(res)
		if err != nil {
			c.Logger.Error("😥 Operator not healthy: ", zap.Error(err), zap.String("IP", res.ip))
			continue
		}
	}
	return nil
}

func (c *Initiator) prepareAndSignMessage(msg wire.SSZMarshaller, msgType wire.TransportType, identifier [24]byte, version []byte) ([]byte, error) {
	// Marshal the provided message
	marshaledMsg, err := msg.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	// Create the transport message
	transportMsg := &wire.Transport{
		Type:       msgType,
		Identifier: identifier,
		Data:       marshaledMsg,
		Version:    version,
	}

	// Marshal the transport message
	tssz, err := transportMsg.MarshalSSZ()
	if err != nil {
		return nil, err
	}

	// Sign the message
	sig, err := crypto.SignRSA(c.PrivateKey, tssz)
	if err != nil {
		return nil, err
	}

	// Create and marshal the signed transport message
	signedTransportMsg := &wire.SignedTransport{
		Message:   transportMsg,
		Signer:    0, // Ensure this value is correctly set as per your application logic
		Signature: sig,
	}
	return signedTransportMsg.MarshalSSZ()
}

func (c *Initiator) processPongMessage(res pongResult) error {
	if res.err != nil {
		return res.err
	}
	signedPongMsg := &wire.SignedTransport{}
	if err := signedPongMsg.UnmarshalSSZ(res.result); err != nil {
		errmsg, parseErr := ParseAsError(res.result)
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
	pub, err := crypto.ParseRSAPubkey(pong.PubKey)
	if err != nil {
		return err
	}
	if err := crypto.VerifyRSA(pub, pongBytes, signedPongMsg.Signature); err != nil {
		return err
	}
	c.Logger.Info("🍎 operator online and healthy", zap.String("ID", fmt.Sprint(signedPongMsg.Signer)), zap.String("IP", res.ip), zap.String("Version", string(signedPongMsg.Message.Version)), zap.String("Public key", string(pong.PubKey)))
	return nil
}

func (c *Initiator) GetCeremonySigs(dkgResults []dkg.Result) (*CeremonySigs, error) {
	// order the results by operatorID
	sort.SliceStable(dkgResults, func(i, j int) bool {
		return dkgResults[i].OperatorID < dkgResults[j].OperatorID
	})
	ceremonySigs := &CeremonySigs{}
	var sigsBytes []byte
	for i := 0; i < len(dkgResults); i++ {
		ceremonySigs.OperatorIDs = append(ceremonySigs.OperatorIDs, dkgResults[i].OperatorID)
		sigsBytes = append(sigsBytes, dkgResults[i].CeremonySig...)
	}
	ceremonySigs.Sigs = hex.EncodeToString(sigsBytes)
	encInitPub, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}
	ceremonySigs.InitiatorPublicKey = hex.EncodeToString(encInitPub)
	ceremonySigs.ValidatorPubKey = "0x" + hex.EncodeToString(dkgResults[0].ValidatorPubKey)
	return ceremonySigs, nil
}
