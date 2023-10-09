package initiator

import (
	"bytes"
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
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"
	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/consts"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// b64 encrypted key length is 256
const encryptedKeyLength = 256

const (
	// MaxEffectiveBalanceInGwei is the max effective balance
	MaxEffectiveBalanceInGwei phase0.Gwei = 32000000000
)

// IsSupportedDepositNetwork returns true if the given network is supported
var IsSupportedDepositNetwork = func(network eth2_key_manager_core.Network) bool {
	return network == eth2_key_manager_core.PyrmontNetwork || network == eth2_key_manager_core.PraterNetwork || network == eth2_key_manager_core.MainNetwork
}

type Operator struct {
	Addr   string
	ID     uint64
	PubKey *rsa.PublicKey
}

type OperatorDataJson struct {
	Addr   string `json:"ip"`
	ID     uint64 `json:"id"`
	PubKey string `json:"public_key"`
}

type Operators map[uint64]Operator

type MockInitiator interface {
	SendAndCollect(op Operator, method string, data []byte) ([]byte, error)
	SendToAll(method string, msg []byte) ([][]byte, error)
	PakeMultiple(id [24]byte, allmsgs [][]byte) (*wire.MultipleSignedTransports, error)
	StartDKG(withdraw []byte, ids []uint64, threshold uint64, fork [4]byte, forkName string, owner common.Address, nonce uint64) (*DepositDataJson, *KeyShares, error)
	CreateVerifyFunc(ops []*wire.Operator) (func(id uint64, msg []byte, sig []byte) error, error)
	ProcessDKGResultResponse(responseResult [][]byte, id [24]byte) ([]dkg.Result, *bls.PublicKey, map[ssvspec_types.OperatorID]*bls.PublicKey, map[ssvspec_types.OperatorID]*bls.Sign, map[ssvspec_types.OperatorID]*bls.Sign, error)
	SendKyberMsgs(kyberDeals [][]byte, id [24]byte) ([][]byte, error)
	SendExchangeMsgs(exchangeMsgs [][]byte, id [24]byte) ([][]byte, error)
	SendInitMsg(init *wire.Init, id [24]byte) ([][]byte, error)
}

type Initiator struct {
	Logger     *zap.Logger
	Client     *req.Client
	Operators  Operators
	VerifyFunc func(id uint64, msg, sig []byte) error
	PrivateKey *rsa.PrivateKey
}

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

type KeyShares struct {
	Version   string           `json:"version"`
	Data      Data             `json:"data"`
	Payload   KeySharesPayload `json:"payload"`
	CreatedAt time.Time        `json:"createdAt"`
}

type Data struct {
	PublicKey string         `json:"publicKey"`
	Operators []OperatorData `json:"operators"`
	Shares    KeySharesKeys  `json:"shares"`
}

type OperatorData struct {
	ID        uint64 `json:"id"`
	PublicKey string `json:"publicKey"`
}

type KeySharesKeys struct {
	PublicKeys    []string `json:"publicKeys"`
	EncryptedKeys []string `json:"encryptedKeys"`
}

type KeySharesPayload struct {
	Readable ReadablePayload `json:"readable"`
	Raw      string          `json:"raw"`
}

type Commits struct {
	ID      string `json:"id"`
	Commits string `json:"commits"`
}

type ReadablePayload struct {
	PublicKey   string   `json:"publicKey"`
	OperatorIDs []uint64 `json:"operatorIds"`
	Shares      string   `json:"shares"`
	Amount      string   `json:"amount"`
	Cluster     string   `json:"cluster"`
}

func GeneratePayload(result []dkg.Result, sigOwnerNonce []byte) (*KeyShares, error) {
	// order the results by operatorID
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].OperatorID < result[j].OperatorID
	})

	shares := KeySharesKeys{
		PublicKeys:    make([]string, 0),
		EncryptedKeys: make([]string, 0),
	}
	operatorData := make([]OperatorData, 0)
	operatorIds := make([]uint64, 0)

	var pubkeys []byte
	var encryptedShares []byte
	for _, operatorResult := range result {
		// Data for forming share string
		pubkeys = append(pubkeys, operatorResult.SharePubKey...)
		encryptedShares = append(encryptedShares, operatorResult.EncryptedShare...)

		encPubKey, err := crypto.EncodePublicKey(operatorResult.PubKeyRSA)
		if err != nil {
			return nil, err
		}
		operatorData = append(operatorData, OperatorData{
			ID:        operatorResult.OperatorID,
			PublicKey: string(encPubKey),
		})
		operatorIds = append(operatorIds, operatorResult.OperatorID)
		shares.PublicKeys = append(shares.PublicKeys, "0x"+hex.EncodeToString(operatorResult.SharePubKey))
		shares.EncryptedKeys = append(shares.EncryptedKeys, base64.StdEncoding.EncodeToString(operatorResult.EncryptedShare))
	}

	data := Data{
		PublicKey: "0x" + hex.EncodeToString(result[0].ValidatorPubKey),
		Operators: operatorData,
		Shares:    shares,
	}
	// Create share string for ssv contract
	sharesData := append(pubkeys, encryptedShares...)
	sharesDataSigned := append(sigOwnerNonce, sharesData...)

	operatorCount := len(result)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := encryptedKeyLength*operatorCount + pubKeysOffset

	if sharesExpectedLength != len(sharesDataSigned) {
		return nil, fmt.Errorf("malformed ssv share data")
	}

	payload := KeySharesPayload{
		Readable: ReadablePayload{
			PublicKey:   "0x" + hex.EncodeToString(result[0].ValidatorPubKey),
			OperatorIDs: operatorIds,
			Shares:      "0x" + hex.EncodeToString(sharesDataSigned),
			Amount:      "Amount of SSV tokens to be deposited to your validator's cluster balance (mandatory only for 1st validator in a cluster)",
			Cluster:     "The latest cluster snapshot data, obtained using the cluster-scanner tool. If this is the cluster's 1st validator then use - {0,0,0,0,0,false}",
		},
	}
	ks := &KeyShares{}
	ks.Version = "v3"
	ks.Data = data
	ks.Payload = payload
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

func New(privKey *rsa.PrivateKey, operatorMap Operators, logger *zap.Logger) *Initiator {
	client := req.C()
	// Set timeout for operator responses
	client.SetTimeout(30 * time.Second)
	c := &Initiator{
		Logger:     logger,
		Client:     client,
		Operators:  operatorMap,
		PrivateKey: privKey,
	}
	return c
}

type opReqResult struct {
	operatorID uint64
	err        error
	result     []byte
}

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
			errarr = append(errarr, res.err)
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

func parseAsError(msg []byte) (error, error) {
	sszerr := &wire.ErrSSZ{}
	err := sszerr.UnmarshalSSZ(msg)
	if err != nil {
		return nil, err
	}

	return errors.New(string(sszerr.Error)), nil
}

func (c *Initiator) VerifyAll(id [24]byte, allmsgs [][]byte) error {
	for i := 0; i < len(allmsgs); i++ {
		msg := allmsgs[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			errmsg, parseErr := parseAsError(msg)
			if parseErr == nil {
				return fmt.Errorf("operator %d returned err: %v", i, errmsg)
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
	return nil
}

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
			errmsg, parseErr := parseAsError(msg)
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

func validatedOperatorData(ids []uint64, operators Operators) ([]*wire.Operator, error) {
	if len(ids) < 4 {
		return nil, fmt.Errorf("minimum supported amount of operators is 4")
	}
	// limit amount of operators
	if len(ids) > 13 {
		return nil, fmt.Errorf("maximum supported amount of operators is 13")
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

func (c *Initiator) messageFlowHandlingInit(init *wire.Init, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
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

func (c *Initiator) messageFlowHandlingReshare(reshare *wire.Reshare, newID [24]byte, oldOperators []*wire.Operator, newOperators []*wire.Operator) ([][]byte, error) {
	c.Logger.Info("phase 1: sending reshare message to old operators")
	allOps := c.JoinSets(oldOperators, newOperators)
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

func (c *Initiator) reconstructAndVerifyDepositData(withdrawCredentials []byte, validatorPubKey *bls.PublicKey, fork [4]byte, forkName string, sigDepositShares map[uint64]*bls.Sign, sharePks map[uint64]*bls.PublicKey) (*DepositDataJson, error) {
	shareRoot, err := crypto.DepositDataRoot(withdrawCredentials, validatorPubKey, getNetworkByFork(fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, err
	}
	// Verify partial signatures and recovered threshold signature
	err = crypto.VerifyPartialSigs(sigDepositShares, sharePks, shareRoot)
	if err != nil {
		return nil, err
	}

	// Recover and verify Master Signature
	// 1. Recover validator pub key
	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(sharePks)
	if err != nil {
		return nil, err
	}

	if !bytes.Equal(validatorPubKey.Serialize(), validatorRecoveredPK.Serialize()) {
		return nil, fmt.Errorf("incoming validator pub key is not equal recovered from shares: want %x, got %x", validatorRecoveredPK.Serialize(), validatorPubKey.Serialize())
	}
	// 2. Recover master signature from shares
	reconstructedDepositMasterSig, err := crypto.RecoverMasterSig(sigDepositShares)
	if err != nil {
		return nil, err
	}
	if !reconstructedDepositMasterSig.VerifyByte(validatorPubKey, shareRoot) {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}

	depositData, root, err := crypto.DepositData(reconstructedDepositMasterSig.Serialize(), withdrawCredentials, validatorPubKey.Serialize(), getNetworkByFork(fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, err
	}
	// Verify deposit data
	depositVerRes, err := crypto.VerifyDepositData(depositData, getNetworkByFork(fork))
	if err != nil {
		return nil, err
	}
	if !depositVerRes {
		return nil, fmt.Errorf("deposit data is invalid")
	}
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, _ := depositMsg.HashTreeRoot()
	// Final checks of prepared deposit data
	if !bytes.Equal(depositData.PublicKey[:], validatorRecoveredPK.Serialize()) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong validator public key %x", depositData.PublicKey[:])
	}
	if !bytes.Equal(depositData.WithdrawalCredentials, crypto.WithdrawalCredentialsHash(withdrawCredentials)) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong withdrawal address %x", depositData.WithdrawalCredentials)
	}
	if !(MaxEffectiveBalanceInGwei == depositData.Amount) {
		return nil, fmt.Errorf("deposit data is invalid. Wrong amount %d", depositData.Amount)
	}

	depositDataJson := &DepositDataJson{
		PubKey:                hex.EncodeToString(validatorPubKey.Serialize()),
		WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
		Amount:                MaxEffectiveBalanceInGwei,
		Signature:             hex.EncodeToString(reconstructedDepositMasterSig.Serialize()),
		DepositMessageRoot:    hex.EncodeToString(depositMsgRoot[:]),
		DepositDataRoot:       hex.EncodeToString(root[:]),
		ForkVersion:           hex.EncodeToString(fork[:]),
		NetworkName:           forkName,
		DepositCliVersion:     "2.5.0",
	}

	return depositDataJson, nil
}

func (c *Initiator) StartDKG(id [24]byte, withdraw []byte, ids []uint64, fork [4]byte, forkName string, owner common.Address, nonce uint64) (*DepositDataJson, *KeyShares, error) {

	ops, err := validatedOperatorData(ids, c.Operators)
	if err != nil {
		return nil, nil, err
	}

	// Add messages verification coming form operators
	verify, err := c.CreateVerifyFunc(ops)
	if err != nil {
		return nil, nil, err
	}
	c.VerifyFunc = verify

	pkBytes, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, nil, err
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
		Fork:                  fork,
		Owner:                 owner,
		Nonce:                 nonce,
		InitiatorPublicKey:    pkBytes,
	}
	c.Logger = c.Logger.With(instanceIDField)

	dkgResult, err := c.messageFlowHandlingInit(init, id, ops)
	if err != nil {
		return nil, nil, err
	}

	dkgResults, validatorPubKey, sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, err := c.ProcessDKGResultResponse(dkgResult, id)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("🏁 DKG completed, verifying deposit data and ssv payload")

	depositDataJson, err := c.reconstructAndVerifyDepositData(init.WithdrawalCredentials, validatorPubKey, fork, forkName, sigDepositShares, sharePks)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("✅ verified deposit data")

	// Verify partial signatures for SSV contract owner+nonce and recovered threshold signature
	data := []byte(fmt.Sprintf("%s:%d", common.Address(init.Owner).String(), init.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))

	err = crypto.VerifyPartialSigs(ssvContractOwnerNonceSigShares, sharePks, hash)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("✅ verified partial signatures from operators")
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig, err := crypto.RecoverMasterSig(ssvContractOwnerNonceSigShares)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("✅ successfully reconstructed master signature from partial signatures (threshold holds)")
	err = crypto.VerifyOwnerNoceSignature(reconstructedOwnerNonceMasterSig.Serialize(), init.Owner, validatorPubKey.Serialize(), uint16(init.Nonce))
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("✅ verified owner and nonce master signature")
	keyshares, err := GeneratePayload(dkgResults, reconstructedOwnerNonceMasterSig.Serialize())
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("✅ verified master signature for ssv contract data")
	return depositDataJson, keyshares, nil
}

func (c *Initiator) StartReshare(newId, oldID [24]byte, oldIDs, newIDs []uint64, owner common.Address, nonce uint64) (*KeyShares, error) {

	oldOps, err := validatedOperatorData(oldIDs, c.Operators)
	if err != nil {
		return nil, err
	}
	newOps, err := validatedOperatorData(newIDs, c.Operators)
	if err != nil {
		return nil, err
	}

	allOps := append(oldOps, newOps...)
	// Add messages verification coming form operators
	verify, err := c.CreateVerifyFunc(allOps)
	if err != nil {
		return nil, err
	}
	c.VerifyFunc = verify

	pkBytes, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, err
	}

	instanceIDField := zap.String("instance_id", hex.EncodeToString(newId[:]))
	c.Logger.Info("🚀 Starting ReSHARING ceremony", zap.String("initiator_id", string(pkBytes)), zap.Uint64s("old_operator_ids", oldIDs), zap.Uint64s("new_operator_ids", newIDs), instanceIDField)

	// compute threshold (3f+1)
	oldThreshold := len(oldIDs) - ((len(oldIDs) - 1) / 3)
	newThreshold := len(newIDs) - ((len(newIDs) - 1) / 3)

	reshare := &wire.Reshare{
		OldOperators:       oldOps,
		NewOperators:       newOps,
		OldT:               uint64(oldThreshold),
		NewT:               uint64(newThreshold),
		OldID:              oldID,
		Owner:              owner,
		Nonce:              nonce,
		InitiatorPublicKey: pkBytes,
	}
	dkgResult, err := c.messageFlowHandlingReshare(reshare, newId, oldOps, newOps)
	if err != nil {
		return nil, err
	}
	dkgResults, _, _, ssvContractOwnerNonceSigShares, err := c.ProcessReshareResultResponse(dkgResult, newId)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("🏁 DKG completed, verifying deposit data and ssv payload")
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig, err := crypto.RecoverMasterSig(ssvContractOwnerNonceSigShares)
	if err != nil {
		return nil, err
	}
	keyshares, err := GeneratePayload(dkgResults, reconstructedOwnerNonceMasterSig.Serialize())
	if err != nil {
		return nil, err
	}
	c.Logger.Info("✅ verified master signature for ssv contract data")
	return keyshares, nil
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

func (c *Initiator) CreateVerifyFunc(ops []*wire.Operator) (func(id uint64, msg []byte, sig []byte) error, error) {
	inst_ops := make(map[uint64]*rsa.PublicKey)
	for _, op := range ops {
		pk, err := crypto.ParseRSAPubkey(op.PubKey)
		if err != nil {
			return nil, err
		}
		inst_ops[op.ID] = pk
	}
	return func(id uint64, msg []byte, sig []byte) error {
		pk, ok := inst_ops[id]
		if !ok {
			return fmt.Errorf("cant find operator, was it provided at operators information file %d", id)
		}
		return crypto.VerifyRSA(pk, msg, sig)
	}, nil
}

func getNetworkByFork(fork [4]byte) eth2_key_manager_core.Network {
	switch fork {
	case [4]byte{0x00, 0x00, 0x10, 0x20}:
		return eth2_key_manager_core.PraterNetwork
	case [4]byte{0, 0, 0, 0}:
		return eth2_key_manager_core.MainNetwork
	default:
		return eth2_key_manager_core.MainNetwork
	}
}

func (c *Initiator) ProcessDKGResultResponse(responseResult [][]byte, id [24]byte) ([]dkg.Result, *bls.PublicKey, map[ssvspec_types.OperatorID]*bls.PublicKey, map[ssvspec_types.OperatorID]*bls.Sign, map[ssvspec_types.OperatorID]*bls.Sign, error) {
	dkgResults := make([]dkg.Result, 0)
	validatorPubKey := bls.PublicKey{}
	sharePks := make(map[ssvspec_types.OperatorID]*bls.PublicKey)
	sigDepositShares := make(map[ssvspec_types.OperatorID]*bls.Sign)
	ssvContractOwnerNonceSigShares := make(map[ssvspec_types.OperatorID]*bls.Sign)
	for i := 0; i < len(responseResult); i++ {
		msg := responseResult[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		// check message type
		if tsp.Message.Type == wire.ErrorMessageType {
			var msgErr string
			err := json.Unmarshal(tsp.Message.Data, &msgErr)
			if err != nil {
				return nil, nil, nil, nil, nil, err
			}
			return nil, nil, nil, nil, nil, fmt.Errorf(msgErr)
		}
		if tsp.Message.Type != wire.OutputMessageType {
			return nil, nil, nil, nil, nil, fmt.Errorf("wrong DKG result message type")
		}
		result := &dkg.Result{}
		if err := result.Decode(tsp.Message.Data); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		// If incoming result is with wrong ID, bail
		if !bytes.Equal(result.RequestID[:], id[:]) {
			return nil, nil, nil, nil, nil, fmt.Errorf("DKG result has wrong ID")
		}
		dkgResults = append(dkgResults, *result)
		if err := validatorPubKey.Deserialize(result.ValidatorPubKey); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		sharePubKey := &bls.PublicKey{}
		if err := sharePubKey.Deserialize(result.SharePubKey); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		sharePks[result.OperatorID] = sharePubKey
		depositShareSig := &bls.Sign{}
		if err := depositShareSig.Deserialize(result.DepositPartialSignature); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		sigDepositShares[result.OperatorID] = depositShareSig
		ownerNonceShareSig := &bls.Sign{}
		if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		ssvContractOwnerNonceSigShares[result.OperatorID] = ownerNonceShareSig
		c.Logger.Debug("Received DKG result from operator", zap.Uint64("ID", result.OperatorID))
	}
	return dkgResults, &validatorPubKey, sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, nil
}

func (c *Initiator) ProcessReshareResultResponse(responseResult [][]byte, id [24]byte) ([]dkg.Result, *bls.PublicKey, map[ssvspec_types.OperatorID]*bls.PublicKey, map[ssvspec_types.OperatorID]*bls.Sign, error) {
	dkgResults := make([]dkg.Result, 0)
	validatorPubKey := bls.PublicKey{}
	sharePks := make(map[ssvspec_types.OperatorID]*bls.PublicKey)
	ssvContractOwnerNonceSigShares := make(map[ssvspec_types.OperatorID]*bls.Sign)
	for i := 0; i < len(responseResult); i++ {
		msg := responseResult[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			return nil, nil, nil, nil, err
		}
		// check message type
		if tsp.Message.Type == wire.ErrorMessageType {
			var msgErr string
			err := json.Unmarshal(tsp.Message.Data, &msgErr)
			if err != nil {
				return nil, nil, nil, nil, err
			}
			return nil, nil, nil, nil, fmt.Errorf(msgErr)
		}
		if tsp.Message.Type != wire.OutputMessageType {
			return nil, nil, nil, nil, fmt.Errorf("wrong DKG result message type")
		}
		result := &dkg.Result{}
		if err := result.Decode(tsp.Message.Data); err != nil {
			return nil, nil, nil, nil, err
		}
		// If incoming result is with wrong ID, bail
		if !bytes.Equal(result.RequestID[:], id[:]) {
			return nil, nil, nil, nil, fmt.Errorf("DKG result has wrong ID")
		}
		dkgResults = append(dkgResults, *result)
		if err := validatorPubKey.Deserialize(result.ValidatorPubKey); err != nil {
			return nil, nil, nil, nil, err
		}
		sharePubKey := &bls.PublicKey{}
		if err := sharePubKey.Deserialize(result.SharePubKey); err != nil {
			return nil, nil, nil, nil, err
		}
		sharePks[result.OperatorID] = sharePubKey
		ownerNonceShareSig := &bls.Sign{}
		if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
			return nil, nil, nil, nil, err
		}
		ssvContractOwnerNonceSigShares[result.OperatorID] = ownerNonceShareSig
		c.Logger.Debug("Received DKG result from operator", zap.Uint64("ID", result.OperatorID))
	}
	return dkgResults, &validatorPubKey, sharePks, ssvContractOwnerNonceSigShares, nil
}

func (c *Initiator) SendInitMsg(init *wire.Init, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	sszInit, err := init.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	initMessage := &wire.Transport{
		Type:       wire.InitMessageType,
		Identifier: id,
		Data:       sszInit,
	}
	tsssz, err := initMessage.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignRSA(c.PrivateKey, tsssz)
	if err != nil {
		return nil, err
	}
	// Create signed init message
	signedInitMsg := &wire.SignedTransport{
		Message:   initMessage,
		Signer:    0,
		Signature: sig,
	}
	signedInitMsgBts, err := signedInitMsg.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	results, err := c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, operators)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Initiator) SendReshareMsg(reshare *wire.Reshare, id [24]byte, ops []*wire.Operator) ([][]byte, error) {
	sszReshare, err := reshare.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	reshareMessage := &wire.Transport{
		Type:       wire.ReshareMessageType,
		Identifier: id,
		Data:       sszReshare,
	}
	tsssz, err := reshareMessage.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	sig, err := crypto.SignRSA(c.PrivateKey, tsssz)
	if err != nil {
		return nil, err
	}
	// Create signed resre message
	signedReshareMsg := &wire.SignedTransport{
		Message:   reshareMessage,
		Signer:    0,
		Signature: sig,
	}
	signedReshareMsgBts, err := signedReshareMsg.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	results, err := c.SendToAll(consts.API_RESHARE_URL, signedReshareMsgBts, ops)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Initiator) SendExchangeMsgs(exchangeMsgs [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	mltpl, err := c.MakeMultiple(id, exchangeMsgs)
	if err != nil {
		return nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	results, err := c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
	if err != nil {
		return nil, err
	}
	return results, nil
}

func (c *Initiator) SendKyberMsgs(kyberDeals [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	mltpl2, err := c.MakeMultiple(id, kyberDeals)
	if err != nil {
		return nil, err
	}

	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	responseResult, err := c.SendToAll(consts.API_DKG_URL, mltpl2byts, operators)
	if err != nil {
		return nil, err
	}
	return responseResult, nil
}

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
			return nil, fmt.Errorf("wrong pub key string")
		}
		pbKey, err := x509.ParsePKIXPublicKey(pemBlock.Bytes)
		if err != nil {
			return nil, err
		}

		opmap[opdata.ID] = Operator{
			Addr:   opdata.Addr,
			ID:     opdata.ID,
			PubKey: pbKey.(*rsa.PublicKey),
		}
	}
	return opmap, nil
}

func (c *Initiator) GetThreshold(ids []uint64) (int, error) {
	if len(ids) < 4 {
		return 0, fmt.Errorf("minimum supported amount of operators is 4")
	}
	// limit amount of operators
	if len(ids) > 13 {
		return 0, fmt.Errorf("maximum supported amount of operators is 13")
	}
	threshold := len(ids) - ((len(ids) - 1) / 3)
	return threshold, nil
}

func (c *Initiator) JoinSets(oldOperators []*wire.Operator, newOperators []*wire.Operator) []*wire.Operator {
	tmp := make(map[uint64]*wire.Operator)
	var set []*wire.Operator
	for _, op := range oldOperators {
		if tmp[op.ID] == nil {
			tmp[op.ID] = op
		}
	}
	for _, op := range newOperators {
		if tmp[op.ID] == nil {
			tmp[op.ID] = op
		}
	}
	for _, op := range tmp {
		set = append(set, op)
	}
	return set
}
