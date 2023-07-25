package client

import (
	"crypto/rsa"
	"errors"
	"fmt"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/consts"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
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

	c.logger.Infof("operator %v responded to %v with %v", op.ID, method, resdata)

	return resdata, nil
}

func (c *Client) SendToAll(method string, msg []byte) ([][]byte, error) {
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
		pkbytes, err := crypto.EncodePublicKey(op.Pubkey)
		if err != nil {
			return err
		}
		parts = append(parts, &wire.Operator{
			ID:     op.ID,
			Pubkey: pkbytes,
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

	//todo handle error being sent back in ssz

	tsssz, err := ts.MarshalSSZ()
	if err != nil {
		return fmt.Errorf("failed marshiling init transport msg to ssz %v", err)
	}

	results, err := c.SendToAll(consts.API_INIT_URL, tsssz)
	if err != nil {
		return fmt.Errorf("failed sending init msg  %v", err)
	}

	c.logger.Infof("Init phase finished, sending exchange messages")

	mltpl, err := c.makeMultiple(id, results)
	if err != nil {
		return err
	}

	mltplbyts, err := mltpl.MarshalSSZ()
	if err != nil {
		return err
	}

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

	//
	//last, err := c.makeMultiple(id, results)
	//if err != nil {
	//	return err
	//}

	//c.logger.Infof("DKG Should be finished now, last results is this: %v", spew.Sdump(last))
	return nil
}
