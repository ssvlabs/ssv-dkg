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
	"github.com/bloxapp/ssv-dkg-tool/pkgs/consts"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/dkg"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/utils"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	"github.com/bloxapp/ssv-spec/types"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
	"github.com/drand/kyber"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/sign/tbls"
	"github.com/google/uuid"
	"github.com/imroc/req/v3"
	"github.com/sirupsen/logrus"
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
	c.logger.Infof("final addr %v", fmt.Sprintf("%v/%v", op.Addr, method))
	res, err := r.Post(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}

	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}

	c.logger.Infof("operator %d responded to %s with %x", op.ID, method, resdata)

	return resdata, nil
}

func (c *Client) SendToAll(method string, msg []byte) ([][]byte, error) {
	// TODO: set timeout for a reply from operators. We should receive all answers to init
	// Also consider to creating a unique init message by adding timestamp
	resc := make(chan opReqResult, len(c.ops))
	for _, op := range c.ops {
		go func(operator Operator) {
			res, err := c.SendAndCollect(operator, method, msg)
			c.logger.Infof("Collected message: method: %s, from: %s", method, operator.Addr)
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
		c.logger.Info("Operator messages are valid. Continue.")

		final.Messages[i] = tsp
	}

	return final, nil
}

func (c *Client) StartDKG(withdraw []byte, ids []uint64, threshold uint64, fork [4]byte, forkName string, owner [20]byte, nonce uint64) error {
	suite := kyber_bls12381.NewBLS12381Suite()
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

	// TODO: we need top check authenticity of the initiator. Consider to add pubkey and signature of the initiator to the init message.
	results, err := c.SendToAll(consts.API_INIT_URL, tsssz)
	if err != nil {
		return fmt.Errorf("error at processing init messages  %v", err)
	}

	c.logger.Info("Exchange round received from all operators, creating combined message")
	mltpl, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}
	c.logger.Info("Marshall exchange response combined message")
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return err
	}
	c.logger.Info("Send exchange response combined message")
	results, err = c.SendToAll(consts.API_DKG_URL, mltplbyts)
	if err != nil {
		return fmt.Errorf("error at processing exchange messages  %v", err)
	}

	c.logger.Infof("Exchange phase finished, sending kyber deals messages")
	mltpl2, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}

	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return err
	}

	responseResult, err := c.SendToAll(consts.API_DKG_URL, mltpl2byts)
	if err != nil {
		return fmt.Errorf("error at processing kyber deal messages  %v", err)
	}

	c.logger.Infof("Got DKG results")

	dkgResults := make([]dkg.Result, 0)
	commitments := make([]kyber.Point, 0)
	var ValidatorPubKey []byte
	sigShares := make([][]byte, 0)
	for i := 0; i < len(responseResult); i++ {
		msg := responseResult[i]
		tsp := &wire.SignedTransport{}
		if err := tsp.UnmarshalSSZ(msg); err != nil {
			return err
		}
		result := &dkg.Result{}
		err := result.Decode(tsp.Message.Data)
		if err != nil {
			return err
		}
		dkgResults = append(dkgResults, *result)
		// Unmarshall public commitments
		commitsFromRes := make([]kyber.Point, 0)
		for _, commit := range result.Commitments {
			point := suite.G1().Point()
			err := point.UnmarshalBinary(commit)
			if err != nil {
				return err
			}
			c.logger.Infof("Commit points %s", point.String())
			commitsFromRes = append(commitsFromRes, point)
		}
		commitments = commitsFromRes
		ValidatorPubKey = result.ValidatorPubKey
		c.logger.Infof("Validator pub %x", ValidatorPubKey)
		sigShares = append(sigShares, result.PartialSignature)
		c.logger.Infof("Result of DKG from an operator %v", result)
	}

	// Collect operators answers as a confirmation of DKG process and prepare deposit data
	c.logger.Infof("Withdrawal Credentials %x", init.WithdrawalCredentials)
	c.logger.Infof("Fork Version %x", init.Fork)
	c.logger.Infof("Domain %x", ssvspec_types.DomainDeposit)
	signRoot, depositData, err := ssvspec_types.GenerateETHDepositData(
		ValidatorPubKey,
		init.WithdrawalCredentials,
		init.Fork,
		ssvspec_types.DomainDeposit,
	)
	amount := phase0.Gwei(types.MaxEffectiveBalanceInGwei)
	depositMsg := &phase0.DepositMessage{
		PublicKey:             depositData.PublicKey,
		WithdrawalCredentials: init.WithdrawalCredentials,
		Amount:                amount,
	}
	depositMsgRoot, _ := depositMsg.HashTreeRoot()

	scheme := tbls.NewThresholdSchemeOnG2(kyber_bls12381.NewBLS12381Suite())
	if err != nil {
		return err
	}

	pubPoly := share.NewPubPoly(suite.G1(), suite.G1().Point().Base(), commitments)

	// Verify partial signatures and recovered threshold signature
	for _, resShare := range dkgResults {
		if err := scheme.VerifyPartial(pubPoly, signRoot, resShare.PartialSignature); err != nil {
			c.logger.Errorf("Error verifying partial sig %s, sig %x, T %d, root %x", err.Error(), resShare.PartialSignature, pubPoly.Threshold(), signRoot)
			return err
		}
	}

	// Recover and verify Master Signature
	depositSig, err := scheme.Recover(pubPoly, signRoot, sigShares, int(init.T), len(init.Operators))
	if err != nil {
		return err
	}

	pubKeyPoint := suite.G1().Point()
	err = pubKeyPoint.UnmarshalBinary(ValidatorPubKey)
	if err != nil {
		return err
	}
	c.logger.Infof("Validator pub key %s", pubKeyPoint.String())
	if err := scheme.VerifyRecovered(pubKeyPoint, signRoot, depositSig); err != nil {
		return err
	}

	// blsSig := phase0.BLSSignature{}
	// copy(blsSig[:], depositSig)
	// depositData.Signature = blsSig

	depositDataRoot, _ := depositData.HashTreeRoot()

	depositDataJson := DepositDataJson{
		PubKey:                hex.EncodeToString(ValidatorPubKey),
		WithdrawalCredentials: hex.EncodeToString(depositData.WithdrawalCredentials),
		Amount:                amount,
		Signature:             hex.EncodeToString(depositSig),
		DepositMessageRoot:    hex.EncodeToString(depositMsgRoot[:]),
		DepositDataRoot:       hex.EncodeToString(depositDataRoot[:]),
		ForkVersion:           hex.EncodeToString(init.Fork[:]),
		NetworkName:           forkName,
		DepositCliVersion:     "2.5.0",
	}
	// Save deposit file
	filepath := fmt.Sprintf("deposit-data_%d.json", time.Now().UTC().Unix())
	fmt.Printf("writing deposit data json to file %s\n", filepath)
	err = utils.WriteJSON(filepath, []DepositDataJson{depositDataJson})

	// Save SSV contract payload
	keyshares := &KeyShares{}
	if err := keyshares.GeneratePayloadV4(dkgResults, hex.EncodeToString(depositSig)); err != nil {
		return fmt.Errorf("HandleGetKeyShares: failed to parse keyshare from dkg results: %w", err)
	}

	filename := fmt.Sprintf("keyshares-%d.json", time.Now().Unix())
	fmt.Printf("writing keyshares to file: %s\n", filename)
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
