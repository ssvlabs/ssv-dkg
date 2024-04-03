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
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/imroc/req/v3"
	"go.uber.org/zap"

	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/bloxapp/ssv-dkg/pkgs/consts"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv-dkg/spec"
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
func (c *Initiator) generateSSVKeysharesPayload(operators []*wire.Operator, dkgResults []*wire.Result, reconstructedOwnerNonceMasterSig *bls.Sign, owner common.Address, nonce uint64) (*wire.KeySharesCLI, error) {
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

	data := []wire.Data{{
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
	ks.Version = "v1.1.0"
	ks.Shares = data
	ks.CreatedAt = time.Now().UTC()
	return ks, nil
}

func GenerateAggregatesKeyshares(keySharesArr []*wire.KeySharesCLI) (*wire.KeySharesCLI, error) {
	var data []wire.Data
	for _, keyShares := range keySharesArr {
		data = append(data, keyShares.Shares...)
	}
	ks := &wire.KeySharesCLI{}
	ks.Version = "v1.1.0"
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
	privKey, _, err := crypto.GenerateRSAKeys()
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
func ValidatedOperatorData(ids []uint64, operators wire.OperatorsCLI) ([]*wire.Operator, error) {
	if len(ids) < 4 {
		return nil, fmt.Errorf("wrong operators len: < 4")
	}
	if len(ids) > 13 {
		return nil, fmt.Errorf("wrong operators len: > 13")
	}
	if len(ids)%3 != 1 {
		return nil, fmt.Errorf("amount of operators should be 4,7,10,13: got %d", ids)
	}

	ops := make([]*wire.Operator, len(ids))
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

		pkBytes, err := crypto.EncodeRSAPublicKey(op.PubKey)
		if err != nil {
			return nil, fmt.Errorf("can't encode public key err: %v", err)
		}
		ops[i] = &wire.Operator{
			ID:     op.ID,
			PubKey: pkBytes,
		}
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
	err = verifyMessageSignatures(id, results, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 1: ✅ verified operator init responses signatures")

	c.Logger.Info("phase 2: ➡️ sending operator data (exchange messages) required for dkg")
	results, err = c.SendExchangeMsgs(results, id, operators)
	if err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, results, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator responses (deal messages) signatures")
	c.Logger.Info("phase 3: ➡️ sending deal dkg data to all operators")
	dkgResult, err := c.SendKyberMsgs(results, id, operators)
	if err != nil {
		return nil, err
	}
	err = verifyMessageSignatures(id, results, c.VerifyMessageSignature)
	if err != nil {
		return nil, err
	}
	c.Logger.Info("phase 2: ✅ verified operator dkg results signatures")
	return dkgResult, nil
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

	pkBytes, err := crypto.EncodeRSAPublicKey(&c.PrivateKey.PublicKey)
	if err != nil {
		return nil, nil, nil, err
	}

	instanceIDField := zap.String("init ID", hex.EncodeToString(id[:]))
	c.Logger.Info("🚀 Starting dkg ceremony", zap.String("initiator public key", string(pkBytes)), zap.Uint64s("operator IDs", ids), instanceIDField)

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
	c.Logger.Info("🏁 DKG completed, verifying deposit data and ssv payload")
	depositDataJson, keyshares, err := c.processDKGResultResponseInitial(dkgResults, init, id)
	if err != nil {
		return nil, nil, nil, err
	}
	c.Logger.Info("✅ verified master signature for ssv contract data")
	if err := crypto.ValidateDepositDataCLI(depositDataJson, common.BytesToAddress(withdraw)); err != nil {
		return nil, nil, nil, err
	}
	if err := crypto.ValidateKeysharesCLI(keyshares, init.Operators, init.Owner, init.Nonce, depositDataJson.PubKey); err != nil {
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
		proofsArray = append(proofsArray, &res.SignedProof)
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

// processDKGResultResponseInitial deserializes incoming DKG result messages from operators after successful initiation ceremony
func (c *Initiator) processDKGResultResponseInitial(dkgResults []*wire.Result, init *wire.Init, requestID [24]byte) (*wire.DepositDataCLI, *wire.KeySharesCLI, error) {
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
	_, depositData, masterSigOwnerNonce, err := spec.ValidateResults(init.Operators, init.WithdrawalCredentials, validatorPK, init.Fork, init.Owner, init.Nonce, requestID, dkgResults)
	if err != nil {
		return nil, nil, err
	}
	network, err := utils.GetNetworkByFork(init.Fork)
	if err != nil {
		return nil, nil, err
	}
	depositDataJson, err := crypto.BuildDepositDataCLI(network, depositData, wire.DepositCliVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to create deposit data json: %v", err)
	}
	c.Logger.Info("✅ deposit data was successfully reconstructed")
	keyshares, err := c.generateSSVKeysharesPayload(init.Operators, dkgResults, masterSigOwnerNonce, init.Owner, init.Nonce)
	if err != nil {
		return nil, nil, err
	}
	return depositDataJson, keyshares, nil
}

func parseDKGResultsFromBytes(responseResult [][]byte, id [24]byte) (dkgResults []*wire.Result, finalErr error) {
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
		result := &wire.Result{}
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
			return nil, fmt.Errorf("operator %d sent wrong validator public key", dkgResults[i].OperatorID)
		}
	}
	return dkgResults, nil
}

// SendInitMsg sends initial DKG ceremony message to participating operators from initiator
func (c *Initiator) SendInitMsg(init *wire.Init, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	signedInitMsgBts, err := c.prepareAndSignMessage(init, wire.InitMessageType, id, c.Version)
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_INIT_URL, signedInitMsgBts, operators, false)
}

// SendExchangeMsgs sends combined exchange messages to each operator participating in DKG ceremony
func (c *Initiator) SendExchangeMsgs(exchangeMsgs [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	mltpl, err := makeMultipleSignedTransports(c.PrivateKey, id, exchangeMsgs)
	if err != nil {
		return nil, err
	}
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_DKG_URL, mltplbyts, operators, false)
}

// SendKyberMsgs sends combined kyber messages to each operator participating in DKG ceremony
func (c *Initiator) SendKyberMsgs(kyberDeals [][]byte, id [24]byte, operators []*wire.Operator) ([][]byte, error) {
	mltpl2, err := makeMultipleSignedTransports(c.PrivateKey, id, kyberDeals)
	if err != nil {
		return nil, err
	}

	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		return nil, err
	}
	return c.SendToAll(consts.API_DKG_URL, mltpl2byts, operators, false)
}

func (c *Initiator) sendResult(resData *wire.ResultData, operators []*wire.Operator, method string, id [24]byte) error {
	signedMsgBts, err := c.prepareAndSignMessage(resData, wire.ResultMessageType, id, c.Version)
	if err != nil {
		return err
	}
	_, err = c.SendToAll(method, signedMsgBts, operators, true)
	if err != nil {
		return err
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
	pub, err := crypto.EncodeRSAPublicKey(&c.PrivateKey.PublicKey)
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
	sig, err := crypto.SignRSA(c.PrivateKey, tssz)
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
	pub, err := crypto.ParseRSAPublicKey(pong.PubKey)
	if err != nil {
		return err
	}
	if err := crypto.VerifyRSA(pub, pongBytes, signedPongMsg.Signature); err != nil {
		return err
	}
	c.Logger.Info("🍎 operator online and healthy", zap.Uint64("ID", pong.ID), zap.String("IP", res.IP), zap.String("Version", string(signedPongMsg.Message.Version)), zap.String("Public key", string(pong.PubKey)))
	return nil
}
