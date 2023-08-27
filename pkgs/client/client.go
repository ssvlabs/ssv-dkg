package client

import (
	"bytes"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"sort"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	spectypes "github.com/bloxapp/ssv-spec/types"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"

	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"
	"github.com/sirupsen/logrus"
	types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/consts"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
)

// b64 encrypted key length is 256
const encryptedKeyLength = 256

// Client will send messages to DKG servers, collect responses and redirects messages to them.

/*
Step 1
					<-->| Server 1
Client -> (Init)	<-->| Server 2
					<-->| Server 3
					<-->| Server 4

Step 2

Client Collects responses
Client creates combined message
SignedMessages = {
	Identifier
	[]SignedMessage
}

						<-->| Server 1
Client -> ([4]Exchange)	<-->| Server 2
						<-->| Server 3
						<-->| Server 4


							<-->| Server 1
Client -> ([4]KyberMessage)	<-->| Server 2
							<-->| Server 3
							<-->| Server 4

*/

func IDtoOperator(id uint64) Operator {
	// TODO: this should either come from server, or from local config or w/e
	// 	we should support multiple ways to get this hence this function is replacble.
	return Operator{}
}

const (
	// MaxEffectiveBalanceInGwei is the max effective balance
	MaxEffectiveBalanceInGwei phase0.Gwei = 32000000000

	// BLSWithdrawalPrefixByte is the BLS withdrawal prefix
	BLSWithdrawalPrefixByte = byte(0)
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

type Client struct {
	Logger     *logrus.Entry
	Client     *req.Client
	Operators  Operators
	VerifyFunc func(id uint64, msg, sig []byte) error
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

func New(operatorMap Operators) *Client {
	client := req.C()
	// Set timeout for operator responses
	client.SetTimeout(30 * time.Second)
	c := &Client{
		Logger:    logrus.NewEntry(logrus.New()),
		Client:    client,
		Operators: operatorMap,
	}
	return c
}

type opReqResult struct {
	operatorID uint64
	err        error
	result     []byte
}

func (c *Client) SendAndCollect(op Operator, method string, data []byte) ([]byte, error) {
	r := c.Client.R()
	// TODO: Consider signing a message
	r.SetBodyBytes(data)
	c.Logger.Debugf("final addr %v", fmt.Sprintf("%v/%v", op.Addr, method))
	res, err := r.Post(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}

	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	c.Logger.Debugf("operator %d responded to %s with %x", op.ID, method, resdata)

	return resdata, nil
}

func (c *Client) SendToAll(method string, msg []byte) ([][]byte, error) {
	resc := make(chan opReqResult, len(c.Operators))
	for _, op := range c.Operators {
		go func(operator Operator) {
			res, err := c.SendAndCollect(operator, method, msg)
			c.Logger.Debugf("Collected message: method: %s, from: %s", method, operator.Addr)
			resc <- opReqResult{
				operatorID: operator.ID,
				err:        err,
				result:     res,
			}
		}(op)
	}
	// TODO: consider a map
	final := make([][]byte, 0, len(c.Operators))

	errarr := make([]error, 0)

	for i := 0; i < len(c.Operators); i++ {
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

func (c *Client) makeMultiple(id [24]byte, allmsgs [][]byte) (*wire.MultipleSignedTransports, error) {
	// todo should we do any validation here? validate the number of msgs?
	// We are collecting responses at SendToAll which gives us int(msg)==int(oprators)
	final := &wire.MultipleSignedTransports{
		Identifier: id,
		Messages:   make([]*wire.SignedTransport, len(allmsgs)),
	}

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
		c.Logger.Debugf("Operator messages are valid. Continue.")

		final.Messages[i] = tsp
	}

	return final, nil
}

func (c *Client) StartDKG(withdraw []byte, ids []uint64, threshold uint64, fork [4]byte, forkName string, owner common.Address, nonce uint64) (*DepositDataJson, *KeyShares, error) {
	// threshold cant be more than number of operators
	if threshold == 0 || threshold > uint64(len(ids)) {
		return nil, nil, fmt.Errorf("wrong threshold")
	}
	parts := make([]*wire.Operator, 0, 0)
	for _, id := range ids {
		op, ok := c.Operators[id]
		if !ok {
			return nil, nil, errors.New("op is not in list")
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

	// make init message
	init := &wire.Init{
		Operators:             parts,
		T:                     threshold,
		WithdrawalCredentials: withdraw,
		Fork:                  fork,
		Owner:                 owner,
		Nonce:                 nonce,
	}

	id := c.NewID()
	results, err := c.SendInitMsg(init, id)
	if err != nil {
		return nil, nil, err
	}
	results, err = c.SendExchangeMsgs(results, id)
	if err != nil {
		return nil, nil, err
	}
	dkgResult, err := c.SendKyberMsgs(results, id)
	if err != nil {
		return nil, nil, err
	}
	c.Logger.Infof("Round 2. Finished successfuly. Got DKG results")

	dkgResults, validatorPubKey, sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, err := c.processDKGResultResponse(dkgResult, id)
	if err != nil {
		return nil, nil, err
	}

	// Collect operators answers as a confirmation of DKG process and prepare deposit data
	c.Logger.Debugf("Withdrawal Credentials %x", init.WithdrawalCredentials)
	c.Logger.Debugf("Fork Version %x", init.Fork)
	c.Logger.Debugf("Domain %x", ssvspec_types.DomainDeposit)

	shareRoot, err := DepositDataRoot(init.WithdrawalCredentials, validatorPubKey, getNetworkByFork(init.Fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, nil, err
	}
	// Verify partial signatures and recovered threshold signature
	err = c.VerifyPartialSigs(dkgResults, sigDepositShares, sharePks, shareRoot)
	if err != nil {
		return nil, nil, err
	}

	// Recover and verify Master Signature
	// 1. Recover validator pub key
	validatorRecoveredPK, err := c.RecoverValidatorPublicKey(sharePks)
	if err != nil {
		return nil, nil, err
	}

	if !bytes.Equal(validatorPubKey.Serialize(), validatorRecoveredPK.Serialize()) {
		return nil, nil, fmt.Errorf("incoming validator pub key isnt equal recovered from shares: want %x, got %x", validatorRecoveredPK.Serialize(), validatorPubKey.Serialize())
	}

	// 2. Recover master signature from shares
	reconstructedDepositMasterSig, err := c.RecoverMasterSig(sigDepositShares, init.T)
	if err != nil {
		return nil, nil, err
	}
	if !reconstructedDepositMasterSig.VerifyByte(validatorPubKey, shareRoot) {
		return nil, nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}

	depositData, root, err := DepositData(reconstructedDepositMasterSig.Serialize(), init.WithdrawalCredentials, validatorPubKey.Serialize(), getNetworkByFork(init.Fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return nil, nil, err
	}
	// Verify deposit data
	depositVerRes, err := VerifyDepositData(depositData, getNetworkByFork(init.Fork))
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
	if !bytes.Equal(depositData.WithdrawalCredentials, withdrawalCredentialsHash(init.WithdrawalCredentials)) {
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
	data := []byte(fmt.Sprintf("%s:%d", init.Owner.String(), init.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	c.Logger.Debugf("Owner, Nonce  %x, %d", init.Owner, init.Nonce)
	c.Logger.Debugf("SSV Keccak 256 of Owner + Nonce  %x", hash)

	err = c.VerifyPartialSigs(dkgResults, ssvContractOwnerNonceSigShares, sharePks, hash)
	if err != nil {
		return nil, nil, err
	}
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig, err := c.RecoverMasterSig(ssvContractOwnerNonceSigShares, init.T)
	if err != nil {
		return nil, nil, err
	}
	if !reconstructedOwnerNonceMasterSig.VerifyByte(validatorPubKey, hash) {
		return nil, nil, fmt.Errorf("owner + nonce signature recovered from shares is invalid")
	}
	err = crypto.VerifyOwnerNoceSignature(reconstructedOwnerNonceMasterSig.Serialize(), init.Owner, validatorPubKey.Serialize(), uint16(init.Nonce))
	if err != nil {
		return nil, nil, err
	}
	keyshares := &KeyShares{}
	if err := keyshares.GeneratePayload(dkgResults, reconstructedOwnerNonceMasterSig.Serialize()); err != nil {
		return nil, nil, fmt.Errorf("handleGetKeyShares: failed to parse keyshare from dkg results: %w", err)
	}
	// key1, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb3dJQkFBS0NBUUVBdkFXRFppc1d4TUV5MGNwdjhoanBBOEMxY1hndWx4eTIrS0M2V2lYajc1OG4yOXhvClNsNHV1SjgwQ2NqQXJqbGQrWkNEWmxvSlhtMk51L0FFOFRaMlBFbVRkVzFwanlOZXU3ZENRa0ZMcXdvckZnUDMKVWdxczdQSEpqSE1mOUtTb1Y0eUxlbkxwYlR0L2tEczJ1Y1c3dStjeG9kUnh3TVFkdmI3b2ZPQWFtWHFHWFpnQwphNHNvdHZmSW9RS1dDaW9MczcvUkM3dHJrUGJONW4rbHQyZWF3UnVIVFNOU1lwR2ZuL253QVE4dUNpbnlKc1BXCkQ0NUhldG9GekNKSlBnNjYzVzE1K1VsWU9tQVJCcWtaSVBISHlXbk5GNlNLa1FqUjYwMnBDdFdORlEyL3BRUWoKblJXbUkrU2FjMHhXRVQ3UUlsVmYxSGZ2NWRnWE9OT05hTTlFU3dJREFRQUJBb0lCQURsYVdTMldJVGpkVWZvcQpqU0ZGTmZiZUZyckpGVFVsSGk4VElDVVZmOFQ5UUhSUmRFS1RIaDlVK05Pdk9BOHRFcHhvMTV3bUJNdVlFVzd0CmxTUmJINC9lUmF2Qk56emhaaWxPaWxpWmdGSnBKS0Z2amthcFdQeGgrTC90OGlaMi81N05FVkxGc0t5UVJLWWoKV2RzckZNd0podHM5YVlHS2tTUHJFeEhjYm1DNE4zVzJPMEd1cngrMUlZZUFYNW9LTzNCNFNnc0FmWG1tK0NGTwp3ZTVxc3BRQy96NU1JSnpkS2VaV3dPRjNhREpnTUlFcmpkYXU0NTVxRFVTRFY4UU5KNjhKR01jNjlFcG1ha0VRCk13MU55MlBVNXVpeTRmU2hVdnZBME5hUURZc0Z4elhCbU9mQUxUMmQ3ZDd6SUgybU8rK0RzNHZWYmZFZVJTRzMKcTA2WDVta0NnWUVBOXJCM0hVUE9kTG9yN1BZMXV0ZmIxckZrVlJ2UlZoVUkvRitzamtqNTVGalNpV3hKVG1sbApCZStQRlBoWi9JVHRuZGlONWF6Qk93YVNzZVpMT3BKaXhnWjg5OWxWMGNPOGNDOW03Q25zSTk5eFBzcEtCaXlpCjMxL3VnWjZnVTNHSEVITW5KR01lN1BjcFBaT3NMMU1rMmt5TFZkZW1kc2NqdHZibWc3YVliQjhDZ1lFQXd4NHgKekpVQ2E0Mldld29qN3lFNWlFMDhjdjY1VFBnNmxEalFOUWs2dUZUNnZzZlRET0xoMnl2ZWtNOGFrWE9CN2grcwpmcUVhd0FuUTA4Z2ZkUi9jQWN2dDZUN1VVdUNWdzVvMUpwVEtmcEIzdTdRbDZsN21wbm9wejNmRjNXa2orWHlxCkNNejVEZGxkTy9PVHRoZlpBOGludUFMVEVGeWVKRm95QmE5QTRsVUNnWUF1VkMzS25UVmt6cUg1T3JRVWh2Mk8KY0hvN1VhSWEzSkIzZFRCZStHMlY2T2lCVG9qbDVQMUlCQm1IQXExRHMyTTh4YkxBYzVWR2xKRndQNlBaT0N5OApxL05FU05qSk1FMXZkRGVNR3NOeWFVQkhYbzVRWW9ta0Vjd2xJN2xRY24yL0pTRXd3RHpLbkJCdXRCRWVRaXNsCnBFSjJ1SzFXbVVlbjBPNnh4ZFVTV1FLQmdGVURzL2tLdCtvNjMrVXVUdWZqVnhqL1ppWkl2RjVBRGU0Rkx4cmMKc1p3ZFVyK0xlM2F5Nkd2Qm1wRUgyL0NpSG11dG0wLzFUQjErYVdITllYOTc2VFZUTUk4ZlZBM2tVdnpPRlBpQgpmaFZWUndZZkFTSTBSVlVtQjAraFJUSXFuSVVZLzFFa1ZpUGxvSXo5blUrSzVvQ1NqaGxNQ2NDb1NqTldwVkw2CndFK2RBb0dCQUtmS1k1aGM2MjRlZWxIcXU2QTFoV2s3VkdoM0x6U0RsQ0ZEYWFWSGM5amJDSUlTRnRSN0VNa2oKMWkwVHBYYmJpR2ZwOEt2QVE3MDVXOTJGbXQvMGRzaUtOWFhVN3dMd0hKVGlPQTdQT2hNMWRjdTBCdW9xeS9XagpQOVZGZ253azVESzVlUFFaMzg5akZVRDlib01tTE0rTUJPaStZTHhHMnZEbWRLOVI5U2pJCi0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==")
	// key2, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFb2dJQkFBS0NBUUVBdnRVRWFlallqY3pBUWhnSTQ0S3dwZlhmOEI2TVlSOE4zMWZFUUtEZENWajl1Q09wCnVybzYzSDdxWXNzMzVGaVdxNmRwMjR3M0dCRTAzR1llU1BSZjBMRUFUQmRiWEJWRjdYZHp6L2xXZStuUk1EbVcKdm1DTUZjRlRPRU5FYmhuTXVjOEQ1K3ZFTmo5cTQzbE4vejhqYTZPYzhLa0QvYThJbTY2bnhmRGEyMXIzM1pJbwpGL1g5d0g2K25EN3Jockx5bzJub1lxaVJpT1NTTkp2R25UY09rMGZySThvbEU2NHVyWHFZcUs3ZmJxc1o3TzY2CnphN2ROTmc3MW1EWHlpdDlSTUlyR3lSME5xN0FUSkxwbytoTERyV2hjSHgzQ1ZvV1BnM25HamE3R25UWFdTYVYKb1JPSnBRVU9oYXgxNVJnZ2FBOHpodGgyOUorNnNNY2R6ZitQRndJREFRQUJBb0lCQUQ5dVh3RTFQSVlsd09JMwpTdjBVdTlMdVgzbFpMaUE2U2tvcXlqa1JQMmVVQlFIb0dNclFqREF1bjRvbk1uVGNYWGpCTlJhZEROTWJKUTc5CmdxT05WeXZ2S2NJaElXVUNUVFFadUkwd3UrYUVXZHhGeUMyUHVnQ2hPaUJCZThWOUhlZkZQKzhmRnlGUkF4NkoKZTd1VUtSbm1VSXhPSWQxNUNNdDJ5cDJvNlpadm0yUzQ1L0JueCtWdFVUWWlKc1QrREpkcWU5VDE2azB6ekdRMAo2bDl1alJRSU9IZFRiYXplUy9MTFVoUWs5Y1R5SXY4OFlaSXEwZmZNZnVibjBNTk5BRGVvbTVLVUpWUjlsNTdnCkVWOFFIUmN1OThPMWFEMVM3dUVoQkdOWGN3cnd4ME4ycW1GSDc3T0k2ZHNDVXZ0Mnh0eEd0RWU0TTVKRnZ6UnEKdi9uM2VjRUNnWUVBNDNJT0RLZUgvM3lmSmRqbjEzekRqUTdvSkFpMzdESDZGTlJBcnJ6dEpuWk90Q3dZeFh3Qgp3Sk9KcndsZlMwNFJ0RytNZ1BVeDRpcXBkN2JOSHFHMFRXZ0x5alhYaElJUWdoSnF5dHYzY3hkNVMzdDdCMHMrCmFVNHhRMGRTOVdoYTNydVBaak5yTHV5MlU3ZmxjUERBMXQzRmEzRTNwdmUrdHN1S2oxeGhCNHNDZ1lFQTFzbzcKU1IxVEdnZzFFa2hVazRnanBtS3d2RjNlT2xDanJiTVNvQTBmWEFDRTNkai9vTld0RkIzK0JHd3R0Z3RDVnhicQpjVlM1R2RoM3BHYVNtVmhBUGRERFVILzA4THR5WWw2N1Y5dVNmN0htVTBzUHhqUU83eXRIcUREejNoeDY5N2c0CmlkN1N2ajFza0JOTWN1SDgwWXJoZzNrSzBrOGdMTnd3TUYvYmFDVUNnWUJnNmRkc3N2SHkvaEgrR1hkb1RXUXgKdGJsYXFWQmRWMG85RjlmYjNPcWI2ZXROUUVEcDNSWU9EWStzUXEwVk5GVzg4WThIMy9KNmNUMDJvbkN5YmFxYgpGUXQ1QlFvcER4YWpwZDlWUXZja1Zrczd5NGkzcWVzVkNkbFoxb2xWd2pwK0Q2TmhvK1UyNEd3c0xmNlk2aXp4CklSd2UxT1ltd2dmRWNlUS9nOWhnVXdLQmdFU0IxaXo0ekhPbUlIOUhVS3FKcG8xQU53eXRoOTdqcjRFTWQ2bFMKNWlpckJiWFlxNWY1N3kxV2I1bXJnMXpuOUczZ29rQXBmS3h3cmFCakV1a1VDOUZyajVCU2I2YUVzdlFMTVFmUgp3Y1UyMGJiSlh5dWhtUTNScVJaTkhzcytIRDU4cEpQYzNTek9YSjBMZXJ1OXRxeUM5bkMvbjZMNmw5R1hIVXVnCmwxTjlBb0dBWkhHQm1RbXkvTTgrZ0ZLWHdXUWgxb2krMmJsODdvMjF2SlVxYituSHF2enVhMUZMNDJPZ2ZQWXQKOGlmaUVzVzZ4RlVZNUJ0MlJvaTY4QW9QSk5HREZnZlNrTS9ER2RUbFdGRzhFempRajRKczZIazZuMGwyV21ydgp2QjJ1YnVVcDk0NVNZSTNIZ215THVna1kxNTZYMEs4NXhwRHFncWNFVUxyZnNBV1d6a009Ci0tLS0tRU5EIFJTQSBQUklWQVRFIEtFWS0tLS0tCg==")
	// key3, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcEFJQkFBS0NBUUVBdlFhZlo0ODJQYXRsYnRrOVdIb2NkMFZ1Y1ZYOThBSXN6cC9rOUVOVjJBTzZJWFBRCnVqU1BtdUZrQTlibThsSllnWTJPb0lQU0RmK1JHWGNMc2R0VHN0QmFDYk8vSkw4WVJ6OTg1REp6OEFGWENTQncKbW5mbzROSFptUjJGMVdMTE5CS2wzdVQ5Q1VLbC9RUnpKRFF1M01hUnp4TkVWZ041a29TU2J3Q3FUM0NIK2NqbgpQU0pIeGhiaTNTaldOSnJFb3ZRUmN3ZUlpYXRrZEdVNWJOUkpRbUtWV2FjOHNWSVg3Y0M0TnhXZEM0bVUzVE8rCmVlei90N2xVcnhSNjdnb21TbGdwaU5weFJ1M2dFajRkSWpIN2xkOVNhbU5sQk94dXk3SUUwQml2bmdJR0grNXAKcXZVTXhoM0N5WkVtMjFHd3JTRFhqcVpwWG92OEUwQkQ5eGY4U3dJREFRQUJBb0lCQUYrVTRMZnA5OEI1VWFJYQpvV1dDNGJBQjROWFlhTDZiS3ZNVWNSNStpZ0xmNTVlUXk2UE1maTBQK1pYamJnWnNVeXEzWEw2WHlYaWdtVXRxCklmUytkZlUrVzdqNk5oWXJ0dWdZRjF3QWt4VnlhQU5LYndYOHlqb2NnczVrMms3TFZQc3d6c1VGdjFtV1pQNnEKNkZvUE5QOFlQWlNiSm52ajUrNkpzTTRHWlJnamJERXhuWU05OFRYYTc1eUJvS2pqc1dwTjJkblB1VjFLWGRjcgowK3lRZzloTUUzZVhHa0U3QTJrb0NCNnF6aW1uRXBxVHZMNjZ2dHM5NXV0LzRUcTAvSGR1aVpwUWdxRHFuV3JIClJydGhoV0ZkeXQvZkhrdEhzYjFRQmUzTytZSTljNFVKVkh5VW9oTWV2Q2NzekpaZ3RBenJEWlJjODVXWUpWdmoKZDNYcmMzRUNnWUVBOU1hekFwK1oyMDh5K2FoZWRYcDJMdzRmUE40ZjYwYVFzNnVaSE9XNG0yWFB4SyswTnpPbwpJZVdSMVVaMFQ1dk5QOCtsMTlXS2RDdFBiVEhpTkYvajFZbXJkc3l6YUNRN3BWVkNwRXd6MlRucExQUmpOMjNnCnZ1ek5MYUdsdzBwN2JBTm5DcEFkaUdQVnpaYUtrWGNDLzk1NHBqUEZHUjVtSWNseXRJdm1YbE1DZ1lFQXhiRi8KNEFVak9PTEszdG5yU1FQV1IrM29IbDI0YWJoM0VNZDhrdDlQSjlkbCtSdGxFVDd0UTZ6TTNud2xFOVhHSERNSwprS3FsYW80Umx5TkpSbTlUT2pzZHpOakQ0S2N0d0EzSjM1TG1HSUs3YlN6UVVmak1ZVktNR2VkbEQ5NFZGWjJWCm5NaEFxRlNXQ0Z1czIrMkNiL2RhQ09WUkFLSFRSN2FTcFhwN2V5a0NnWUVBOFk2QkxBNmJCRDJWWGFGVmpuUEsKMjhjQTlzMXlESG8zNU1kc000TlVlaTZ3S2pjSER3N3dWbnM2UHBIbnlJUkZ1anBPUE1Ca2dSNFlwUGI4ZDVsRgp1djdBY2wyeWt3eG12Rk4yajdNUDI4aDFuMEtTQXlweEI1bWpKZXdITE1GOUtXdjJMUXRweWFaVVlTMjJFN1d5CkJSWGtWSWgwY3NSNEg5R3dYQkpQeGpjQ2dZQkR4YVRqNUg3OXFtb0gyY2NhUWRGODJTZEErYm9WckNKTlEwWUcKaDcxNEdCU2lRR3oyYTQ4bEt5RVVpSlNoWnlEQ1hCRWNKUlFPSW1RUFh3NW9zaE5qSEE4TVFhZHM1WUwrbXZ1QQp4TGhTNE1abUYvM1dqQ2RzbWNManduclg1TGR2c0pVd3FVblpLeDVBQVVXU0k2c2F2VDVGWEcvWGVxS1dyQlU3CjIzQm5lUUtCZ1FEMFZhSXRtY3BnYTBOQnhLSEEwOWU3UXZ3V1FKL1Q0RkQyV2VmblI4cmN4QWVja0YraXdnSTkKQ0MvNzNYejNzVmlWZG9wMmRQRUpCWGtVOTFSanBJanpVUkVwT0RURjBham1XWlAxR2JZeWo0V0VpTWRBMnZZbgpHaUFDS3ZzajdCRzlOVVZ4d1V1d1pKdENKNmQzc1NIN0N1L2hqdGFTZmFKaGZNdDIvUXFWWXc9PQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=")
	// key4, _ := base64.StdEncoding.DecodeString("LS0tLS1CRUdJTiBSU0EgUFJJVkFURSBLRVktLS0tLQpNSUlFcFFJQkFBS0NBUUVBeFRWM2I5OHU4NmtzcEhQcWgrS2QrNEd3SVJ4SHBEekRmNWVzeGNnK3FpOW9sNERGCmplUXMrbGloeUp5cGdOMXJwdTlQVnR5cXp2K3k5cEVNa0VXTi9iMFRCZ1EwSnlPN2Y0aWJjV3lRRys0aFVRL1cKY3h1ZW5aUDA3S0VwTjh4Tk8xN3BzbmhRMXRqQVhybDNGN1lYaVl1eXlnRG1rbDRiNitQNHoyM2FHTVVIS2dOcgp5aFlZTFV4dWdycDVRTnJTV3lXNXFtb2EvYnJDenQ2RFJYb1VTbklKSlJRWk9LY2dyR0owdUFiMkNGa2wvTG5oCklxT2RZZ21aUG9oRmprVEorRnZNdkZsMjAwZ1BHbVpxUS9MMmwzZkF2aFliVlEyVFV5S2ZTaithdnVZQVlmeEoKeG5OcWlmdkNkVGNmQzc3c0N0eFFERWVjY0pTVnVDbGZWeTFZWXdJREFRQUJBb0lCQUZ1UzJFTTZmN0xsZTdWaApuaVk3Tk9EMDk3Um9UVndXV3pHRVhOWDZoaDdBcFBDMCt3ZElUUnB5emEwNkVmdWsxYmhPcDZqT0R3TFArV3BGCk1IQk4zQUZYS3Q1QVZYZFhRRm1ZTlpZVnMxVkUzbk9seHc3c1pGc0h1Vk9vQWx2R29wWlBISFdqS09hYS83ajgKcGpCOGZiR0JEU1NBQnBFdzRnWkhkZUhjUU1uKzRoMDNoS0FpYTZucE5CM2ExNFBpVXNEeVRwNFR2dGlKNFVaNAppVEs0U0NKQzRkZWhzRnZNNXJTSnhLREFYTzNrQnEvQXk1S1RTRFFHK2hqemJYcUZiQXVqV283UllMOVpYK2hNCmE1NlNwYkNRd0dyTENnb1c3bDNzamdrRTFYd1JLUGpwNVovZVpVOENvWVg4VFVHeU4rdUxjWGdVYlZ0bnVjdmEKQ1FNTkZ3RUNnWUVBekk2R291cjF6c1BNTytZaXBqNlNtY1pkL3NVTGNDYWZPVE5lVFhvZEduaXVYUjZ2UjRycAp2WTR4NStQU0FNV1ZYc2w3WjF6QS93RmhxcUJtdjV0T2pFRlM0S1BaSERDQnVmMjFSOFFsRmpGa0Qvdi90dE1qCnBIcnU0MXF5dXVzM3pZU2VqZnRwdVFaa1ZLcnljSFFBR2JaRnZPMkY2MmNpSmF5OW1vTTROVDBDZ1lFQTlzM2gKTFZtTVp1dFlHdDBTcWhwS3VQVWJsaVgwb2RxSW5KVVhvZW9KMXQ3Y3JCSTFYOVVRaThEcFJheVlDaU5DN3ByUgp3eGxZQjVIS1JRZEZSWDdJSjM5enZScU44Nm9Yb2xzS1ZxRXl5WDJUcnFSaFVrdENqMkF2bUgyR0tEdERTYWxBCjhVZWpvSEU0US80OWhXeHBBT3RPZFBEeDFMUytjSy8vcGVWRTNoOENnWUVBb0xXbFg2QWJxT3U1cktHOVBVRlIKNmxDb0RuNSs0d2prOVlxL0h6MitXY3JRcXNadHpWWjlGM2o5Q29PNXZQTit6QzZkcm5KNENxRHFPNlN6dFB2dQp0VkNwTFdadEw3R0lhampDMFBSd2NzUXhLa0hCQU1GWGNtVkhCQWFBLzB2SDFzYkh6eUxrU0FLV2x0S0xrUUFDCkNERmxEdTdKMVUxOHpYNnVwQk5OK0wwQ2dZRUE3TEZkOXlRZVpzWGw1VDJIbk9OQ0xrZkRnU2c5aU13UW9Eck0KUTFnMHY0RlVtU0dOVnE3OEEwdXJiRXF1TldyRDBobGdlbjlmMFVLY2ZiOFBUQ3Jld2lLVldSS1NlTkR6Z1oxVwpPT2EzMGsxQXlRaVUzVnVZSmZEVk5LV05lQi85MURNaU9VTy9SU3ZRRGtWUnN4ZlpUQ3hmUGYrbHJaejUxeEN6CldPS2NQWGtDZ1lFQXd1U2ZkRmlqWEdIK0F0Um9YMFZrRDVCbCt1SElGRWpNaFhhMXZqc2ZjY2pyN2RobXVMS3oKd1FINW1heVRJTXlmbFRKb1ZPWnAxZnovN0ZQT0ZhaFNpWjA0dnFUYTVYbGpUSzlac3FGMFo0ZUhOdm1BazQvWAppUVZwVVQ2SE5EMit5aDU0T1BrdWVmbEJNd1FwUTVpdmdqenlPaUhKcTRwcjZ2WW9mM3JjcGdrPQotLS0tLUVORCBSU0EgUFJJVkFURSBLRVktLS0tLQo=")
	// k1, err := crypto.ConvertPemToPrivateKey(string(key1))
	// k2, err := crypto.ConvertPemToPrivateKey(string(key2))
	// k3, err := crypto.ConvertPemToPrivateKey(string(key3))
	// k4, err := crypto.ConvertPemToPrivateKey(string(key4))
	// if err != nil {
	// 	return err
	// }
	// opPrivKeys := []*rsa.PrivateKey{k1, k2, k3, k4}

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

func sharesToBytes(publicKeys []string, privateKeys []string, prefix string) string {
	encryptedShares, _ := decodeEncryptedShares(privateKeys)
	arrayPublicKeys := bytes.Join(toArrayByteSlices(publicKeys), []byte{})
	arrayEncryptedShares := bytes.Join(toArrayByteSlices(encryptedShares), []byte{})
	pkPsBytes := append(arrayPublicKeys, arrayEncryptedShares...)
	return "0x" + prefix + hex.EncodeToString(pkPsBytes)
}

func decodeEncryptedShares(encodedEncryptedShares []string) ([]string, error) {
	var result []string
	for _, item := range encodedEncryptedShares {
		// Decode the base64 string
		decoded, err := base64.StdEncoding.DecodeString(item)
		if err != nil {
			return nil, err
		}

		// Encode the decoded bytes as a hexadecimal string with '0x' prefix
		result = append(result, "0x"+hex.EncodeToString(decoded))
	}
	return result, nil
}

func toArrayByteSlices(input []string) [][]byte {
	var result [][]byte
	for _, str := range input {
		bytes, _ := hex.DecodeString(str[2:]) // remove the '0x' prefix and decode the hex string to bytes
		result = append(result, bytes)
	}
	return result
}

func (c *Client) CreateVerifyFunc(ops []*wire.Operator) (func(id uint64, msg []byte, sig []byte) error, error) {
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

func DepositDataRoot(withdrawalPubKey []byte, publicKey *bls.PublicKey, network eth2_key_manager_core.Network, amount phase0.Gwei) ([]byte, error) {
	if !IsSupportedDepositNetwork(network) {
		return nil, fmt.Errorf("network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: withdrawalCredentialsHash(withdrawalPubKey),
		Amount:                amount,
	}
	copy(depositMessage.PublicKey[:], publicKey.Serialize())

	objRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}

	// Compute domain
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate domain: %s", err)
	}

	signingData := phase0.SigningData{
		ObjectRoot: objRoot,
	}
	copy(signingData.Domain[:], domain[:])

	root, err := signingData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine the root hash of signing container: %s", err)
	}

	return root[:], nil
}

func DepositData(masterSig, withdrawalPubKey, publicKey []byte, network eth2_key_manager_core.Network, amount phase0.Gwei) (*phase0.DepositData, [32]byte, error) {
	if !IsSupportedDepositNetwork(network) {
		return nil, [32]byte{}, fmt.Errorf("network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: withdrawalCredentialsHash(withdrawalPubKey),
		Amount:                amount,
	}
	copy(depositMessage.PublicKey[:], publicKey)

	objRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}

	// Compute domain
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to calculate domain: %s", err)
	}

	signingData := phase0.SigningData{
		ObjectRoot: objRoot,
	}
	copy(signingData.Domain[:], domain[:])

	signedDepositData := &phase0.DepositData{
		Amount:                amount,
		WithdrawalCredentials: depositMessage.WithdrawalCredentials,
	}
	copy(signedDepositData.PublicKey[:], publicKey)
	copy(signedDepositData.Signature[:], masterSig)

	depositDataRoot, err := signedDepositData.HashTreeRoot()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}

	return signedDepositData, depositDataRoot, nil
}

// withdrawalCredentialsHash forms a 32 byte hash of the withdrawal public
// address.
//
// The specification is as follows:
//
//	withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX_BYTE
//	withdrawal_credentials[1:] == hash(withdrawal_pubkey)[1:]
//
// where withdrawal_credentials is of type bytes32.
func withdrawalCredentialsHash(withdrawalPubKey []byte) []byte {
	h := util.SHA256(withdrawalPubKey)
	return append([]byte{BLSWithdrawalPrefixByte}, h[1:]...)[:32]
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

func VerifyDepositData(depositData *phase0.DepositData, network eth2_key_manager_core.Network) (bool, error) {
	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                depositData.Amount,
	}
	copy(depositMessage.PublicKey[:], depositData.PublicKey[:])

	depositMsgRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return false, err
	}

	sigBytes := make([]byte, len(depositData.Signature))
	copy(sigBytes, depositData.Signature[:])
	sig, err := types.BLSSignatureFromBytes(sigBytes)
	if err != nil {
		return false, err
	}

	container := &phase0.SigningData{
		ObjectRoot: depositMsgRoot,
	}

	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return false, err
	}
	copy(container.Domain[:], domain[:])
	signingRoot, err := container.HashTreeRoot()
	if err != nil {
		return false, err
	}

	var pubkeyBytes [48]byte
	copy(pubkeyBytes[:], depositData.PublicKey[:])

	pubkey, err := types.BLSPublicKeyFromBytes(pubkeyBytes[:])
	if err != nil {
		return false, err
	}
	return sig.Verify(signingRoot[:], pubkey), nil
}

func (c *Client) processDKGResultResponse(responseResult [][]byte, id [24]byte) ([]dkg.Result, *bls.PublicKey, map[ssvspec_types.OperatorID]*bls.PublicKey, map[ssvspec_types.OperatorID]*bls.Sign, map[ssvspec_types.OperatorID]*bls.Sign, error) {
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
		c.Logger.Debugf("Validator pub %x", validatorPubKey.Serialize())
		sharePubKey := &bls.PublicKey{}
		if err := sharePubKey.Deserialize(result.SharePubKey); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		sharePks[result.DepositPartialSignatureIndex] = sharePubKey
		depositShareSig := &bls.Sign{}
		if err := depositShareSig.Deserialize(result.DepositPartialSignature); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		sigDepositShares[result.DepositPartialSignatureIndex] = depositShareSig
		ownerNonceShareSig := &bls.Sign{}
		if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
			return nil, nil, nil, nil, nil, err
		}
		ssvContractOwnerNonceSigShares[result.DepositPartialSignatureIndex] = ownerNonceShareSig
		c.Logger.Debugf("Result of DKG from an operator %v", result)
	}
	return dkgResults, &validatorPubKey, sharePks, sigDepositShares, ssvContractOwnerNonceSigShares, nil
}

func (c *Client) SendInitMsg(init *wire.Init, id [24]byte) ([][]byte, error) {
	sszinit, err := init.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("failed marshiling init msg to ssz %v", err)
	}

	ts := &wire.Transport{
		Type:       wire.InitMessageType,
		Identifier: id,
		Data:       sszinit,
	}

	tsssz, err := ts.MarshalSSZ()
	if err != nil {
		return nil, fmt.Errorf("failed marshiling init transport msg to ssz %v", err)
	}
	c.Logger.Info("Round 1. Sending init message to operators")
	// TODO: we need top check authenticity of the initiator. Consider to add pubkey and signature of the initiator to the init message.
	results, err := c.SendToAll(consts.API_INIT_URL, tsssz)
	if err != nil {
		return nil, fmt.Errorf("error at processing init messages  %v", err)
	}
	return results, nil
}

func (c *Client) SendExchangeMsgs(exchangeMsgs [][]byte, id [24]byte) ([][]byte, error) {
	c.Logger.Info("Round 1. Parsing init responses")
	mltpl, err := c.makeMultiple(id, exchangeMsgs)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("Round 1. Exchange round received from all operators, verified signatures\")")
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	c.Logger.Info("Round 1. Send exchange response combined message to operators / receive kyber deal messages")
	results, err := c.SendToAll(consts.API_DKG_URL, mltplbyts)
	if err != nil {
		return nil, fmt.Errorf("error at processing exchange messages  %v", err)
	}
	return results, nil
}

func (c *Client) SendKyberMsgs(kyberDeals [][]byte, id [24]byte) ([][]byte, error) {
	mltpl2, err := c.makeMultiple(id, kyberDeals)
	if err != nil {
		return nil, err
	}

	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	c.Logger.Infof("Round 2. Exchange phase finished, sending kyber deal messages")
	responseResult, err := c.SendToAll(consts.API_DKG_URL, mltpl2byts)
	if err != nil {
		return nil, fmt.Errorf("error at processing kyber deal messages  %v", err)
	}
	return responseResult, nil
}

func (c *Client) NewID() [24]byte {
	var id [24]byte
	copy(id[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	b := uuid.New() // random ID for each new DKG initiation
	copy(id[8:], b[:])
	return id
}

func (c *Client) VerifyPartialSigs(dkgResults []dkg.Result, sigShares map[uint64]*bls.Sign, sharePks map[uint64]*bls.PublicKey, data []byte) error {
	for _, resShare := range dkgResults {
		if !sigShares[resShare.DepositPartialSignatureIndex].VerifyByte(sharePks[resShare.DepositPartialSignatureIndex], data) {
			return fmt.Errorf("error verifying partial deposit signature: sig %x, root %x", sigShares[resShare.DepositPartialSignatureIndex].Serialize(), data)
		}
	}
	return nil
}

func (c *Client) RecoverValidatorPublicKey(sharePks map[uint64]*bls.PublicKey) (*bls.PublicKey, error) {
	validatorRecoveredPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for operatorID, pk := range sharePks {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", operatorID)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *pk)
	}
	if err := validatorRecoveredPK.Recover(pkVec, idVec); err != nil {
		return nil, fmt.Errorf("error recovering validator pub key from shares")
	}
	return &validatorRecoveredPK, nil
}
func (c *Client) RecoverMasterSig(sigDepositShares map[uint64]*bls.Sign, threshold uint64) (*bls.Sign, error) {
	reconstructedDepositMasterSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for operatorID, sig := range sigDepositShares {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", operatorID)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		sigVec = append(sigVec, *sig)

		if len(sigVec) >= int(threshold) {
			break
		}
	}
	if err := reconstructedDepositMasterSig.Recover(sigVec, idVec); err != nil {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	return &reconstructedDepositMasterSig, nil
}

func validateKeyShares(keyshares *KeyShares, owner common.Address, nonce uint16, operatorPrivateKeys []*rsa.PrivateKey) error {
	valPubKey, err := hex.DecodeString(keyshares.Payload.Readable.PublicKey)
	if err != nil {
		return err
	}
	shares, err := hex.DecodeString(keyshares.Payload.Readable.Shares)
	if err != nil {
		return err
	}
	ev := ContractValidatorAdded{
		Owner:       owner,
		OperatorIds: keyshares.Payload.Readable.OperatorIDs,
		PublicKey:   valPubKey,
		Shares:      shares,
	}

	operatorCount := len(ev.OperatorIds)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := encryptedKeyLength*operatorCount + pubKeysOffset

	if sharesExpectedLength != len(ev.Shares) {
		return &MalformedEventError{Err: fmt.Errorf("shares length is not correct")}
	}

	signature := ev.Shares[:signatureOffset]
	sharePublicKeys := splitBytes(ev.Shares[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := splitBytes(ev.Shares[pubKeysOffset:], len(ev.Shares[pubKeysOffset:])/operatorCount)
	// verify sig
	err = crypto.VerifyOwnerNoceSignature(signature, ev.Owner, ev.PublicKey, nonce)
	if err != nil {
		return err
	}
	err = validatorAddedEventToShare(ev, sharePublicKeys, encryptedKeys, operatorPrivateKeys)
	if err != nil {
		return err
	}
	return nil
}

func validatorAddedEventToShare(
	event ContractValidatorAdded,
	sharePublicKeys [][]byte,
	encryptedKeys [][]byte,
	operatorPrivateKeys []*rsa.PrivateKey,
) error {
	pk := bls.PublicKey{}
	if err := pk.Deserialize(event.PublicKey); err != nil {
		return &MalformedEventError{
			Err: fmt.Errorf("failed to deserialize validator public key: %w", err),
		}
	}

	var shareSecret *bls.SecretKey

	committee := make([]*spectypes.Operator, 0)
	for i := range event.OperatorIds {
		operatorID := event.OperatorIds[i]
		committee = append(committee, &spectypes.Operator{
			OperatorID: operatorID,
			PubKey:     sharePublicKeys[i],
		})

		shareSecret = &bls.SecretKey{}
		decryptedSharePrivateKey, err := rsaencryption.DecodeKey(operatorPrivateKeys[i], encryptedKeys[i])
		if err != nil {
			return &MalformedEventError{
				Err: fmt.Errorf("could not decrypt share private key: %w", err),
			}
		}
		if err = shareSecret.SetHexString(string(decryptedSharePrivateKey)); err != nil {
			return &MalformedEventError{
				Err: fmt.Errorf("could not set decrypted share private key: %w", err),
			}
		}
		if !bytes.Equal(shareSecret.GetPublicKey().Serialize(), sharePublicKeys[i]) {
			return &MalformedEventError{
				Err: errors.New("share private key does not match public key"),
			}
		}
	}

	return nil
}

// MalformedEventError is returned when event is malformed
type MalformedEventError struct {
	Err error
}

func (e *MalformedEventError) Error() string {
	return e.Err.Error()
}

func (e *MalformedEventError) Unwrap() error {
	return e.Err
}

// ContractValidatorAdded represents a ValidatorAdded event raised by the Contract contract.
type ContractValidatorAdded struct {
	Owner       common.Address
	OperatorIds []uint64
	PublicKey   []byte
	Shares      []byte
	Cluster     ISSVNetworkCoreCluster
}

// ISSVNetworkCoreCluster is an auto generated low-level Go binding around an user-defined struct.
type ISSVNetworkCoreCluster struct {
	ValidatorCount  uint32
	NetworkFeeIndex uint64
	Index           uint64
	Active          bool
	Balance         *big.Int
}

type ShareEncryptionKeyProvider = func() (*rsa.PrivateKey, bool, error)

func splitBytes(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}
