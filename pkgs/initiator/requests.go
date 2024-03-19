package initiator

import (
	"errors"
	"fmt"
	"io"

	"go.uber.org/zap"

	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

// opReqResult structure to represent http communication messages incoming to initiator from operators
type opReqResult struct {
	operatorID uint64
	err        error
	result     []byte
}

// SendAndCollect ssends http message to operator and read the response
func (c *Initiator) SendAndCollect(op wire.OperatorCLI, method string, data []byte, checkError bool) ([]byte, error) {
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
	if checkError {
		if res.StatusCode < 200 || res.StatusCode >= 300 {
			errmsg, parseErr := wire.ParseAsError(resdata)
			if parseErr == nil {
				return nil, fmt.Errorf("%v", errmsg)
			}
			return nil, fmt.Errorf("operator %d failed with: %w", op.ID, errors.New(string(resdata)))
		}
	}
	return resdata, nil
}

// GetAndCollect request Get at operator route
func (c *Initiator) GetAndCollect(op wire.OperatorCLI, method string) ([]byte, error) {
	r := c.Client.R()
	res, err := r.Get(fmt.Sprintf("%v/%v", op.Addr, method))
	if err != nil {
		return nil, err
	}
	resdata, err := io.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	c.Logger.Debug("operator responded", zap.String("IP", op.Addr), zap.String("method", method), zap.Int("status", res.StatusCode))
	return resdata, nil
}

// SendToAll sends http messages to all operators. Makes sure that all responses are received
func (c *Initiator) SendToAll(method string, msg []byte, operators []*wire.Operator, checkError bool) ([][]byte, error) {
	resc := make(chan opReqResult, len(operators))
	for _, wireOp := range operators {
		operator := c.Operators.ByID(wireOp.ID)
		if operator == nil {
			return nil, fmt.Errorf("operator ID: %d not found in operators list", wireOp.ID)
		}
		go func() {
			res, err := c.SendAndCollect(*operator, method, msg, checkError)
			resc <- opReqResult{
				operatorID: operator.ID,
				err:        err,
				result:     res,
			}
		}()
	}
	final := make([][]byte, 0, len(operators))

	errarr := make([]error, 0)

	for i := 0; i < len(operators); i++ {
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
