package client

import (
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/consts"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	ssvspec_types "github.com/bloxapp/ssv-spec/types"
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
	logger *logrus.Entry
	clnt   *req.Client
	ops    Operators
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
	// Consider to sign a message
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
		final.Messages[i] = tsp
	}

	return final, nil
}

func (c *Client) StartDKG(withdraw []byte, ids []uint64) error {

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

	// make init message
	init := &wire.Init{
		Operators:             parts,
		T:                     consts.Threshold,
		WithdrawalCredentials: withdraw,
		Fork:                  consts.Fork,
	}

	sszinit, err := init.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("failed marshiling init msg to ssz %v", err)
	}

	id := wire.NewIdentifier([]byte("1234567894561234567894561321231"), 1)

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
		return fmt.Errorf("failed sending init msg  %v", err)
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
		return err
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

	results, err = c.SendToAll(consts.API_DKG_URL, mltpl2byts)
	if err != nil {
		return err
	}

	c.logger.Infof("Got DKG results")

	// Collect operators answers as a confirmation of DKG process and prepare deposit data
	validatorPK, _ := hex.DecodeString("b3d50de8d77299da8d830de1edfb34d3ce03c1941846e73870bb33f6de7b8a01383f6b32f55a1d038a4ddcb21a765194")
	withdrawalCredentials, _ := hex.DecodeString("005b55a6c968852666b132a80f53712e5097b0fca86301a16992e695a8e86f16")

	signingRoot, _, err := ssvspec_types.GenerateETHDepositData(
		validatorPK,
		withdrawalCredentials,
		ssvspec_types.MainNetwork.ForkVersion(),
		ssvspec_types.DomainDeposit,
	)

	toSignData := KeySign{
		ValidatorPK: validatorPK,
		SigningRoot: signingRoot,
	}
	enc, err := toSignData.Encode()
	
	// Send the root to sign
	results, err = c.SendToAll("sign", enc)
	if err != nil {
		return err
	}

	return nil
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