package initiator

import (
	"bytes"
	"crypto/rsa"
	"crypto/sha256"
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
	"github.com/google/uuid"
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

// Initiator will send messages to DKG servers, collect responses and redirects messages to them.

/*
Step 1
					<-->| operator 1
Initiator -> (Init)	<-->| operator 2
					<-->| operator 3
					<-->| operator 4

Step 2

Initiator Collects responses
Initiator creates combined message
SignedMessages = {
	Identifier
	[]SignedMessage
}

						<-->| operator 1
Initiator -> ([4]Exchange)	<-->| operator 2
						<-->| operator 3
						<-->| operator 4


							<-->| operator 1
Initiator -> ([4]KyberMessage)	<-->| operator 2
							<-->| operator 3
							<-->| operator 4

*/

func IDtoOperator(id uint64) Operator {
	// TODO: this should either come from server, or from local config or w/e
	// 	we should support multiple ways to get this hence this function is replacble.
	return Operator{}
}

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

type ReadablePayload struct {
	PublicKey   string   `json:"publicKey"`
	OperatorIDs []uint64 `json:"operatorIds"`
	Shares      string   `json:"shares"`
	Amount      string   `json:"amount"`
	Cluster     string   `json:"cluster"`
}

func (ks *KeyShares) GeneratePayload(result []dkg.Result, sigOwnerNonce []byte) error {
	shares := KeySharesKeys{
		PublicKeys:    make([]string, 0),
		EncryptedKeys: make([]string, 0),
	}
	operatorData := make([]OperatorData, 0)
	operatorIds := make([]uint64, 0)

	// order the results by operatorID
	sort.SliceStable(result, func(i, j int) bool {
		return result[i].OperatorID < result[j].OperatorID
	})

	var pubkeys []byte
	var encryptedShares []byte
	for _, operatorResult := range result {
		// Data for forming share string
		pubkeys = append(pubkeys, operatorResult.SharePubKey...)
		encryptedShares = append(encryptedShares, operatorResult.EncryptedShare...)

		encPubKey, err := crypto.EncodePublicKey(operatorResult.PubKeyRSA)
		if err != nil {
			return err
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
		return fmt.Errorf("malformed ssv share data")
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

	ks.Version = "v3"
	ks.Data = data
	ks.Payload = payload
	ks.CreatedAt = time.Now().UTC()
	return nil
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
	// TODO: Consider signing a message
	r.SetBodyBytes(data)
	c.Logger.Debug(fmt.Sprintf("final addr %v/%v", op.Addr, method))
	res, err := r.Post(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}
	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Logger.Debug(fmt.Sprintf("operator %d responded to %s with %x", op.ID, method, resdata))
	return resdata, nil
}

func (c *Initiator) SendToAll(method string, msg []byte, operatorsIDs []*wire.Operator) ([][]byte, error) {
	resc := make(chan opReqResult, len(operatorsIDs))
	for _, op := range operatorsIDs {
		go func(operator Operator) {
			res, err := c.SendAndCollect(operator, method, msg)
			c.Logger.Debug(fmt.Sprintf("Collected message: method: %s, from: %s", method, operator.Addr))
			resc <- opReqResult{
				operatorID: operator.ID,
				err:        err,
				result:     res,
			}
		}(c.Operators[op.ID])
	}
	// TODO: consider a map
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
		// Unmarshalling should include sig validation
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			// try parsing an error
			errmsg, parseErr := parseAsError(msg)
			if parseErr == nil {
				return nil, fmt.Errorf("msg %d returned: %v", i, errmsg)
			}
			return nil, err
		}
		signedBytes, err := tsp.Message.MarshalSSZ()
		if err != nil {
			return nil, err
		}
		// Verify that incoming messages have valid DKG ceremony ID
		if !bytes.Equal(id[:], tsp.Message.Identifier[:]) {
			return nil, fmt.Errorf("incoming message has wrong ID. Aborting. Operator %d, msg ID %x", tsp.Signer, tsp.Message.Identifier[:])
		}
		// Verification operator signatures
		if err := c.VerifyFunc(tsp.Signer, signedBytes, tsp.Signature); err != nil {
			return nil, err
		}
		c.Logger.Info(fmt.Sprintf("Successfully verified incoming DKG message type %s signature: from %d", tsp.Message.Type.String(), tsp.Signer))
		c.Logger.Debug("Operator messages are valid. Continue.")

		final.Messages[i] = tsp
		allMsgsBytes = append(allMsgsBytes, msg...)
	}
	// sign message by initiator
	c.Logger.Info(fmt.Sprintf("Signing combined messages from operators with initiator public key, ID: %x", sha256.Sum256(c.PrivateKey.N.Bytes())))
	sig, err := crypto.SignRSA(c.PrivateKey, allMsgsBytes)
	if err != nil {
		return nil, err
	}
	final.Signature = sig
	return final, nil
}

func (c *Initiator) StartDKG(id [24]byte, withdraw []byte, ids []uint64, fork [4]byte, forkName string, owner common.Address, nonce uint64) (*DepositDataJson, *KeyShares, error) {
	// compute threshold (3f+1)
	threshold, err := c.GetThreshold(ids)
	if err != nil {
		return nil, nil, err
	}
	// check that operator ids are unique
	if err := c.validateOpIDs(ids); err != nil {
		return nil, nil, err
	}
	parts := make([]*wire.Operator, 0)
	for _, id := range ids {
		op, ok := c.Operators[id]
		if !ok {
			return nil, nil, errors.New("operator is not in the list")
		}
		pkBytes, err := crypto.EncodePublicKey(op.PubKey)
		if err != nil {
			return nil, nil, err
		}
		parts = append(parts, &wire.Operator{
			ID:     op.ID,
			PubKey: pkBytes,
		})
	}
	// Add messages verification coming form operators
	verify, err := c.CreateVerifyFunc(parts)
	if err != nil {
		return nil, nil, err
	}
	c.VerifyFunc = verify
	pkBytes, err := crypto.EncodePublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info(fmt.Sprintf("Initiator ID: %x", sha256.Sum256(c.PrivateKey.PublicKey.N.Bytes())))
	// make init message
	init := &wire.Init{
		Operators:             parts,
		T:                     uint64(threshold),
		WithdrawalCredentials: withdraw,
		Fork:                  fork,
		Owner:                 owner,
		Nonce:                 nonce,
		InitiatorPublicKey:    pkBytes,
	}

	results, err := c.SendInitMsg(init, id, parts)
	if err != nil {
		return nil, nil, err
	}
	results, err = c.SendExchangeMsgs(results, id, parts)
	if err != nil {
		return nil, nil, err
	}
	dkgResult, err := c.SendKyberMsgs(results, id, parts)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("Round 2. Finished successfully. Got DKG results")

	dkgResults, validatorPubKey, sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, err := c.ProcessDKGResultResponse(dkgResult, id)
	if err != nil {
		return nil, nil, err
	}

	// Collect operators answers as a confirmation of DKG process and prepare deposit data
	c.Logger.Debug(fmt.Sprintf("Withdrawal Credentials %x", init.WithdrawalCredentials))
	c.Logger.Debug(fmt.Sprintf("Fork Version %x", init.Fork))
	c.Logger.Debug(fmt.Sprintf("Domain %x", ssvspec_types.DomainDeposit))

	shareRoot, err := crypto.DepositDataRoot(init.WithdrawalCredentials, validatorPubKey, getNetworkByFork(init.Fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, nil, err
	}
	// Verify partial signatures and recovered threshold signature
	err = crypto.VerifyPartialSigs(sigDepositShares, sharePks, shareRoot)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("Round 2. Post verification. Successfully verified partial signatures of deposit data from operator DKG results")
	// Recover and verify Master Signature
	// 1. Recover validator pub key
	validatorRecoveredPK, err := crypto.RecoverValidatorPublicKey(sharePks)
	if err != nil {
		return nil, nil, err
	}

	if !bytes.Equal(validatorPubKey.Serialize(), validatorRecoveredPK.Serialize()) {
		return nil, nil, fmt.Errorf("incoming validator pub key isnt equal recovered from shares: want %x, got %x", validatorRecoveredPK.Serialize(), validatorPubKey.Serialize())
	}
	c.Logger.Info(fmt.Sprintf("Round 2. Post verification. Successfully recovered validator public key from shares %x", validatorRecoveredPK.Serialize()))
	// 2. Recover master signature from shares
	reconstructedDepositMasterSig, err := crypto.RecoverMasterSig(sigDepositShares)
	if err != nil {
		return nil, nil, err
	}
	if !reconstructedDepositMasterSig.VerifyByte(validatorPubKey, shareRoot) {
		return nil, nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	c.Logger.Info("Round 2. Post verification. Successfully recovered master signature from shares")
	depositData, root, err := crypto.DepositData(reconstructedDepositMasterSig.Serialize(), init.WithdrawalCredentials, validatorPubKey.Serialize(), getNetworkByFork(init.Fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, nil, err
	}
	// Verify deposit data
	depositVerRes, err := crypto.VerifyDepositData(depositData, getNetworkByFork(init.Fork))
	if err != nil {
		return nil, nil, err
	}
	if !depositVerRes {
		return nil, nil, fmt.Errorf("deposit data is invalid")
	}
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, _ := depositMsg.HashTreeRoot()
	// Final checks of prepared deposit data
	if !bytes.Equal(depositData.PublicKey[:], validatorRecoveredPK.Serialize()) {
		return nil, nil, fmt.Errorf("deposit data is invalid. Wrong validator public key %x", depositData.PublicKey[:])
	}
	if !bytes.Equal(depositData.WithdrawalCredentials, crypto.WithdrawalCredentialsHash(init.WithdrawalCredentials)) {
		return nil, nil, fmt.Errorf("deposit data is invalid. Wrong withdrawal address %x", depositData.WithdrawalCredentials)
	}
	if !(MaxEffectiveBalanceInGwei == depositData.Amount) {
		return nil, nil, fmt.Errorf("deposit data is invalid. Wrong amount %d", depositData.Amount)
	}
	depositDataJson := &DepositDataJson{
		PubKey:                hex.EncodeToString(validatorPubKey.Serialize()),
		WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
		Amount:                MaxEffectiveBalanceInGwei,
		Signature:             hex.EncodeToString(reconstructedDepositMasterSig.Serialize()),
		DepositMessageRoot:    hex.EncodeToString(depositMsgRoot[:]),
		DepositDataRoot:       hex.EncodeToString(root[:]),
		ForkVersion:           hex.EncodeToString(init.Fork[:]),
		NetworkName:           forkName,
		DepositCliVersion:     "2.5.0",
	}

	// Verify partial signatures for SSV contract owner+nonce and recovered threshold signature
	data := []byte(fmt.Sprintf("%s:%d", common.Address(init.Owner).String(), init.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	c.Logger.Debug(fmt.Sprintf("Owner, Nonce  %x, %d", init.Owner, init.Nonce))
	c.Logger.Debug(fmt.Sprintf("SSV Keccak 256 of Owner + Nonce  %x", hash))

	err = crypto.VerifyPartialSigs(ssvContractOwnerNonceSigShares, sharePks, hash)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("Round 2. Post verification. Successfully verified partial signatures for ssv contract data")
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig, err := crypto.RecoverMasterSig(ssvContractOwnerNonceSigShares)
	if err != nil {
		return nil, nil, err
	}
	if !reconstructedOwnerNonceMasterSig.VerifyByte(validatorPubKey, hash) {
		return nil, nil, fmt.Errorf("owner + nonce signature recovered from shares is invalid")
	}
	c.Logger.Info("Round 2. Post verification. Successfully reconstructed master signature for ssv contract data")
	err = crypto.VerifyOwnerNoceSignature(reconstructedOwnerNonceMasterSig.Serialize(), init.Owner, validatorPubKey.Serialize(), uint16(init.Nonce))
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Info("Round 2. Post verification. Successfully verified master signature for ssv contract data")
	keyshares := &KeyShares{}
	if err := keyshares.GeneratePayload(dkgResults, reconstructedOwnerNonceMasterSig.Serialize()); err != nil {
		return nil, nil, fmt.Errorf("handleGetKeyShares: failed to parse keyshare from dkg results: %w", err)
	}
	return depositDataJson, keyshares, nil
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
			return errors.New("ops not exist for this instance")
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
			return nil, nil, nil, nil, nil, fmt.Errorf("wrong incoming message type")
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
		c.Logger.Debug(fmt.Sprintf("Validator pub %x", validatorPubKey.Serialize()))
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
		c.Logger.Debug(fmt.Sprintf("Result of DKG from an operator %x", result.ValidatorPubKey))
	}
	return dkgResults, &validatorPubKey, sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, nil
}

func (c *Initiator) SendInitMsg(init *wire.Init, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	sszinit, err := init.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("failed marshiling init msg to ssz %v", err)
	}

	initMessage := &wire.Transport{
		Type:       wire.InitMessageType,
		Identifier: id,
		Data:       sszinit,
	}

	tsssz, err := initMessage.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("failed marshiling init transport msg to ssz %v", err)
	}
	sig, err := crypto.SignRSA(c.PrivateKey, tsssz)
	if err != nil {
		return nil, fmt.Errorf("error at processing init messages  %v", err)
	}
	// Create signed init message
	signedInitMsg := &wire.SignedTransport{
		Message:   initMessage,
		Signer:    0,
		Signature: sig,
	}
	signedInitMsgBts, err := signedInitMsg.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("error at processing init messages  %v", err)
	}
	c.Logger.Info("round 1. Sending init message to operators")
	results, err := c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, operators)
	if err != nil {
		return nil, fmt.Errorf("error at processing init messages  %v", err)
	}
	return results, nil
}

func (c *Initiator) SendExchangeMsgs(exchangeMsgs [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	c.Logger.Info("round 1. Parsing init responses")
	mltpl, err := c.MakeMultiple(id, exchangeMsgs)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("round 1. Exchange round received from all operators, verified signatures\")")
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	c.Logger.Info("round 1. Send exchange response combined message to operators / receive kyber deal messages")
	results, err := c.SendToAll(consts.API_DKG_URL, mltplbyts, operators)
	if err != nil {
		return nil, fmt.Errorf("error at processing exchange messages  %v", err)
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
	c.Logger.Info("round 2. Exchange phase finished, sending kyber deal messages")
	responseResult, err := c.SendToAll(consts.API_DKG_URL, mltpl2byts, operators)
	if err != nil {
		return nil, fmt.Errorf("error at processing kyber deal messages  %v", err)
	}
	return responseResult, nil
}

func (c *Initiator) NewID() [24]byte {
	var id [24]byte
	copy(id[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	b := uuid.New() // random ID for each new DKG initiation
	copy(id[8:], b[:])
	return id
}

func (c *Initiator) validateOpIDs(ids []uint64) error {
	opMap := make(map[uint64]bool)
	for _, id := range ids {
		if opMap[id] {
			return fmt.Errorf("operators ids should be unique in the list")
		}
		opMap[id] = true
	}
	return nil
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
			return nil, fmt.Errorf("invalid operator URL")
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
