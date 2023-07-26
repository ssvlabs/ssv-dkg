package client

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/consts"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	"github.com/davecgh/go-spew/spew"
	"github.com/imroc/req/v3"
	"github.com/sirupsen/logrus"
	"io"
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
	Pubkey *rsa.PublicKey
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

	// make init message
	init := &wire.Init{
		Operators:             ids,
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

	//for _, r := range results {
	//	errmsg, err := wire.GetErr(r)
	//	if err == nil {
	//		c.logger.Error("Got error from server ", errmsg)
	//		return errmsg
	//	}
	//}
	c.logger.Info("Init round received, creating combined message")
	mltpl, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}
	c.logger.Info("Marshall init response combined message")
	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return err
	}
	c.logger.Info("Send init response combined message")
	results, err = c.SendToAll(consts.API_DKG_URL, mltplbyts)
	if err != nil {
		return err
	}

	c.logger.Info("DKG round response received, creating combined message")
	mltpl2, err := c.makeMultiple(id, results)
	// TODO: fix unmarshal error
	if err != nil {
		c.logger.Error(err)
		return err
	}
	c.logger.Info("Marshall response to DKG round message")
	mltpl2byts, err := mltpl2.MarshalSSZ()
	if err != nil {
		c.logger.Error(err)
		return err
	}
	c.logger.Info("Send combined DKG round response message")
	results, err = c.SendToAll(consts.API_DKG_URL, mltpl2byts)
	if err != nil {
		return err
	}

	last, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}

	spew.Dump(last)
	//this should probably be final result
	//results =
	// pack results together dissminate results to all
	return nil
}
