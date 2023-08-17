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
	"sort"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
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
	"github.com/bloxapp/ssv-dkg-tool/pkgs/utils"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
)

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

type Operators map[uint64]Operator

type Client struct {
	logger     *logrus.Entry
	clnt       *req.Client
	ops        Operators
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
	Data      KeySharesData    `json:"data"`
	Payload   KeySharesPayload `json:"payload"`
	CreatedAt time.Time        `json:"createdAt"`
}

type KeySharesData struct {
	PublicKey string         `json:"publicKey"`
	Operators []OperatorData `json:"operators"`
}

type OperatorData struct {
	ID          uint32 `json:"id"`
	OperatorKey string `json:"operatorKey"`
}

type KeySharesKeys struct {
	PublicKeys    []string `json:"publicKeys"`
	EncryptedKeys []string `json:"encryptedKeys"`
}

type KeySharesPayload struct {
	Readable ReadablePayload `json:"readable"`
}

type ReadablePayload struct {
	PublicKey   string   `json:"publicKey"`
	OperatorIDs []uint32 `json:"operatorIds"`
	Shares      string   `json:"shares"`
	Amount      string   `json:"amount"`
	Cluster     string   `json:"cluster"`
}

func (ks *KeyShares) GeneratePayloadV4(result []dkg.Result, ownerPrefix string) error {
	shares := KeySharesKeys{
		PublicKeys:    make([]string, 0),
		EncryptedKeys: make([]string, 0),
	}
	operatorData := make([]OperatorData, 0)
	operatorIds := make([]uint32, 0)
	for _, operatorResult := range result {
		operatorData = append(operatorData, OperatorData{
			ID:          operatorResult.OperatorID,
			OperatorKey: operatorResult.PubKeyRSA.N.String(),
		})
		operatorIds = append(operatorIds, operatorResult.OperatorID)
		shares.PublicKeys = append(shares.PublicKeys, "0x"+hex.EncodeToString(operatorResult.SharePubKey))
		shares.EncryptedKeys = append(shares.EncryptedKeys, base64.StdEncoding.EncodeToString(operatorResult.EncryptedShare))
	}

	sort.SliceStable(operatorIds, func(i, j int) bool {
		return operatorIds[i] < operatorIds[j]
	})

	sort.SliceStable(operatorData, func(i, j int) bool {
		return operatorData[i].ID < operatorData[j].ID
	})

	data := KeySharesData{
		PublicKey: "0x" + hex.EncodeToString(result[0].ValidatorPubKey),
		Operators: operatorData,
	}

	payload := KeySharesPayload{
		Readable: ReadablePayload{
			PublicKey:   "0x" + hex.EncodeToString(result[0].ValidatorPubKey),
			OperatorIDs: operatorIds,
			Shares:      sharesToBytes(shares.PublicKeys, shares.EncryptedKeys, ownerPrefix),
			Amount:      "Amount of SSV tokens to be deposited to your validator's cluster balance (mandatory only for 1st validator in a cluster)",
			Cluster:     "The latest cluster snapshot data, obtained using the cluster-scanner tool. If this is the cluster's 1st validator then use - {0,0,0,0,0,false}",
		},
	}

	ks.Version = "v4"
	ks.Data = data
	ks.Payload = payload
	ks.CreatedAt = time.Now().UTC()
	return nil
}

func New(opmap Operators) *Client {
	clnt := req.C()
	c := &Client{
		logger: logrus.NewEntry(logrus.New()),
		clnt:   clnt,
		ops:    opmap,
	}
	return c
}

type opReqResult struct {
	opid uint64
	err  error
	res  []byte
}

func (c *Client) SendAndCollect(op Operator, method string, data []byte) ([]byte, error) {
	r := c.clnt.R()
	// TODO: Consider signing a message
	r.SetBodyBytes(data)
	c.logger.Debugf("final addr %v", fmt.Sprintf("%v/%v", op.Addr, method))
	res, err := r.Post(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}

	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	c.logger.Debugf("operator %d responded to %s with %x", op.ID, method, resdata)

	return resdata, nil
}

func (c *Client) SendToAll(method string, msg []byte) ([][]byte, error) {
	// TODO: set timeout for a reply from operators. We should receive all answers to init
	// Also consider to creating a unique init message by adding timestamp
	resc := make(chan opReqResult, len(c.ops))
	for _, op := range c.ops {
		go func(operator Operator) {
			res, err := c.SendAndCollect(operator, method, msg)
			c.logger.Debugf("Collected message: method: %s, from: %s", method, operator.Addr)
			resc <- opReqResult{
				opid: operator.ID,
				err:  err,
				res:  res,
			}
		}(op)
	}
	// TODO: consider a map
	final := make([][]byte, 0, len(c.ops))

	errarr := make([]error, 0)

	for i := 0; i < len(c.ops); i++ {
		res := <-resc
		if res.err != nil {
			errarr = append(errarr, res.err)
			continue
		}
		final = append(final, res.res)
	}

	finalerr := error(nil)

	if len(errarr) > 0 {
		finalerr = errors.Join(errarr...)
	}

	return final, finalerr
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
		c.logger.Debugf("Operator messages are valid. Continue.")

		final.Messages[i] = tsp
	}

	return final, nil
}

func (c *Client) StartDKG(withdraw []byte, ids []uint64, threshold uint64, fork [4]byte, forkName string, owner [20]byte, nonce uint64) error {

	parts := make([]*wire.Operator, 0, 0)
	for _, id := range ids {
		op, ok := c.ops[id]
		if !ok {
			return errors.New("op is not in list")
		}
		pkBytes, err := crypto.EncodePublicKey(op.PubKey)
		if err != nil {
			return err
		}
		parts = append(parts, &wire.Operator{
			ID:     op.ID,
			PubKey: pkBytes,
		})
	}
	// Add messages verification coming form operators
	verify, err := c.CreateVerifyFunc(parts)
	if err != nil {
		return err
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

	sszinit, err := init.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("failed marshiling init msg to ssz %v", err)
	}

	// id := wire.NewIdentifier([]byte("1234567894561234567894561321231"), 1)
	var id [24]byte
	copy(id[:8], []byte{0, 0, 0, 0, 0, 0, 0, 0})
	b := uuid.New() // random ID for each new DKG initiation
	copy(id[8:], b[:])

	ts := &wire.Transport{
		Type:       wire.InitMessageType,
		Identifier: id,
		Data:       sszinit,
	}

	tsssz, err := ts.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("failed marshiling init transport msg to ssz %v", err)
	}
	c.logger.Info("Round 1. Sending init message to operators")
	// TODO: we need top check authenticity of the initiator. Consider to add pubkey and signature of the initiator to the init message.
	results, err := c.SendToAll(consts.API_INIT_URL, tsssz)
	if err != nil {
		return fmt.Errorf("error at processing init messages  %v", err)
	}

	c.logger.Info("Round 1. Exchange round received from all operators, creating combined message and verifying signatures")
	mltpl, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return err
	}
	c.logger.Info("Round 1. Send exchange response combined message to operators / receive kyber deal messages")
	results, err = c.SendToAll(consts.API_DKG_URL, mltplbyts)
	if err != nil {
		return fmt.Errorf("error at processing exchange messages  %v", err)
	}

	mltpl2, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}

	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return err
	}
	c.logger.Infof("Round 2. Exchange phase finished, sending kyber deal messages")
	responseResult, err := c.SendToAll(consts.API_DKG_URL, mltpl2byts)
	if err != nil {
		return fmt.Errorf("error at processing kyber deal messages  %v", err)
	}

	c.logger.Infof("Round 2. Finished successfuly. Got DKG results")

	dkgResults := make([]dkg.Result, 0)
	validatorPubKey := bls.PublicKey{}
	sharePks := make(map[ssvspec_types.OperatorID]*bls.PublicKey)
	sigDepositShares := make(map[ssvspec_types.OperatorID]*bls.Sign)
	ssvContractOwnerNonceSigShares := make(map[ssvspec_types.OperatorID]*bls.Sign)
	for i := 0; i < len(responseResult); i++ {
		msg := responseResult[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			return err
		}
		result := &dkg.Result{}
		if err := result.Decode(tsp.Message.Data); err != nil {
			return err
		}
		dkgResults = append(dkgResults, *result)
		if err := validatorPubKey.Deserialize(result.ValidatorPubKey); err != nil {
			return err
		}
		c.logger.Debugf("Validator pub %x", validatorPubKey.Serialize())
		sharePubKey := &bls.PublicKey{}
		if err := sharePubKey.Deserialize(result.SharePubKey); err != nil {
			return err
		}
		sharePks[result.DepositPartialSignatureIndex] = sharePubKey
		depositShareSig := &bls.Sign{}
		if err := depositShareSig.Deserialize(result.DepositPartialSignature); err != nil {
			return err
		}
		sigDepositShares[result.DepositPartialSignatureIndex] = depositShareSig
		ownerNonceShareSig := &bls.Sign{}
		if err := ownerNonceShareSig.Deserialize(result.OwnerNoncePartialSignature); err != nil {
			return err
		}
		ssvContractOwnerNonceSigShares[result.DepositPartialSignatureIndex] = ownerNonceShareSig
		c.logger.Debugf("Result of DKG from an operator %v", result)
	}

	// Collect operators answers as a confirmation of DKG process and prepare deposit data
	c.logger.Debugf("Withdrawal Credentials %x", init.WithdrawalCredentials)
	c.logger.Debugf("Fork Version %x", init.Fork)
	c.logger.Debugf("Domain %x", ssvspec_types.DomainDeposit)

	shareRoot, err := DepositDataRoot(init.WithdrawalCredentials, &validatorPubKey, getNetworkByFork(init.Fork), MaxEffectiveBalanceInGwei)

	// Verify partial signatures and recovered threshold signature
	for _, resShare := range dkgResults {
		if !sigDepositShares[resShare.DepositPartialSignatureIndex].VerifyByte(sharePks[resShare.DepositPartialSignatureIndex], shareRoot) {
			return fmt.Errorf("error verifying partial deposit signature %s, sig %x, root %x", err.Error(), sigDepositShares[resShare.DepositPartialSignatureIndex].Serialize(), shareRoot)
		}
	}

	// Recover and verify Master Signature

	// 1. Recover validator pub key
	validatorRecoveredPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for operatorID, pk := range sharePks {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", operatorID)); err != nil {
			return err
		}
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *pk)
	}
	if err := validatorRecoveredPK.Recover(pkVec, idVec); err != nil {
		return fmt.Errorf("error recovering validator pub key from shares")
	}

	if !bytes.Equal(validatorPubKey.Serialize(), validatorRecoveredPK.Serialize()) {
		return fmt.Errorf("incoming validator pub key isnt equal recovered from shares: want %x, got %x", validatorRecoveredPK.Serialize(), validatorPubKey.Serialize())
	}

	// 2. Recover master signature from shares
	reconstructedDepositMasterSig := bls.Sign{}
	idVec = make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for operatorID, sig := range sigDepositShares {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", operatorID)); err != nil {
			return err
		}
		idVec = append(idVec, blsID)
		sigVec = append(sigVec, *sig)

		if len(sigVec) >= int(init.T) {
			break
		}
	}
	if err := reconstructedDepositMasterSig.Recover(sigVec, idVec); err != nil {
		return fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	if !reconstructedDepositMasterSig.VerifyByte(&validatorPubKey, shareRoot) {
		return fmt.Errorf("deposit root signature recovered from shares is invalid")
	}

	depositData, root, err := DepositData(reconstructedDepositMasterSig.Serialize(), init.WithdrawalCredentials, validatorPubKey.Serialize(), getNetworkByFork(init.Fork), MaxEffectiveBalanceInGwei)
	if err != nil {
		return err
	}
	// Verify deposit data
	depositVerRes, err := VerifyDepositData(depositData, getNetworkByFork(init.Fork))
	if err != nil {
		return err
	}
	if !depositVerRes {
		return fmt.Errorf("deposit data is invalid")
	}
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, _ := depositMsg.HashTreeRoot()
	// Final checks of prepared deposit data
	if !bytes.Equal(depositData.PublicKey[:], validatorRecoveredPK.Serialize()) {
		return fmt.Errorf("deposit data is invalid. Wrong validator public key %x", depositData.PublicKey[:])
	}
	if !bytes.Equal(depositData.WithdrawalCredentials, withdrawalCredentialsHash(init.WithdrawalCredentials)) {
		return fmt.Errorf("deposit data is invalid. Wrong withdrawal address %x", depositData.WithdrawalCredentials)
	}
	if !(MaxEffectiveBalanceInGwei == depositData.Amount) {
		return fmt.Errorf("deposit data is invalid. Wrong amount %d", depositData.Amount)
	}
	depositDataJson := DepositDataJson{
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
	// Save deposit file
	filepath := fmt.Sprintf("deposit-data_%d.json", time.Now().UTC().Unix())
	c.logger.Infof("DKG finished. All data is validated. Writing deposit data json to file %s\n", filepath)
	err = utils.WriteJSON(filepath, []DepositDataJson{depositDataJson})
	if err != nil {
		return err
	}
	// Verify partial signatures for SSV contract owner+nonce and recovered threshold signature
	data := []byte(fmt.Sprintf("%s:%d", init.Owner, init.Nonce))
	hash := eth_crypto.Keccak256([]byte(data))
	c.logger.Debugf("Owner, Nonce  %x, %d", init.Owner, init.Nonce)
	c.logger.Debugf("SSV Keccak 256 of Owner + Nonce  %x", hash)

	for _, resShare := range dkgResults {
		if !ssvContractOwnerNonceSigShares[resShare.DepositPartialSignatureIndex].VerifyByte(sharePks[resShare.DepositPartialSignatureIndex], hash) {
			return fmt.Errorf("error verifying partial deposit signature %s, sig %x, root %x", err.Error(), ssvContractOwnerNonceSigShares[resShare.DepositPartialSignatureIndex].Serialize(), shareRoot)
		}
	}
	// Recover and verify Master Signature for SSV contract owner+nonce
	reconstructedOwnerNonceMasterSig := bls.Sign{}
	idVec = make([]bls.ID, 0)
	sigOwnerNonceVec := make([]bls.Sign, 0)
	for operatorID, sig := range ssvContractOwnerNonceSigShares {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", operatorID)); err != nil {
			return err
		}
		idVec = append(idVec, blsID)
		sigOwnerNonceVec = append(sigOwnerNonceVec, *sig)

		if len(sigOwnerNonceVec) >= int(init.T) {
			break
		}
	}
	if err := reconstructedOwnerNonceMasterSig.Recover(sigOwnerNonceVec, idVec); err != nil {
		return err
	}
	if !reconstructedOwnerNonceMasterSig.VerifyByte(&validatorPubKey, hash) {
		return fmt.Errorf("owner + nonce signature recovered from shares is invalid")
	}

	keyshares := &KeyShares{}
	if err := keyshares.GeneratePayloadV4(dkgResults, reconstructedOwnerNonceMasterSig.GetHexString()); err != nil {
		return fmt.Errorf("handleGetKeyShares: failed to parse keyshare from dkg results: %w", err)
	}

	filename := fmt.Sprintf("keyshares-%d.json", time.Now().Unix())
	c.logger.Infof("DKG finished. All data is validated. Writing keyshares to file: %s\n", filename)
	return utils.WriteJSON(filename, keyshares)
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
