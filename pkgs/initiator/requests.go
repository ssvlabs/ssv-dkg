package initiator

import (
	"errors"
	"fmt"
	"io"
	"strings"

	"go.uber.org/zap"

	spec "github.com/ssvlabs/dkg-spec"
	"github.com/ssvlabs/ssv-dkg/pkgs/wire"
)

// opReqResult structure to represent http communication messages incoming to initiator from operators
type opReqResult struct {
	operatorID uint64
	err        error
	result     []byte
}

// SendAndCollect ssends http message to operator and read the response
func (c *Initiator) SendAndCollect(op wire.OperatorCLI, method string, data []byte) ([]byte, error) {
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
	c.Logger.Debug("operator responded", zap.Uint64("operator", op.ID), zap.String("IP", op.Addr), zap.String("method", method), zap.Int("status", res.StatusCode))
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		errString, err := wire.ParseAsError(resdata)
		if err != nil {
			return nil, fmt.Errorf("cant parse error message: %w", err)
		}
		return nil, fmt.Errorf("operator %d failed with: %w, probably of old version, please upgrade", op.ID, errors.New(errString))
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
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		errString, err := wire.ParseAsError(resdata)
		if err != nil {
			return nil, fmt.Errorf("cant parse error message: %w", err)
		}
		return nil, fmt.Errorf("operator failed with: %w, probably of old version, please upgrade", errors.New(errString))
	}
	return resdata, nil
}

// SendToAll sends http messages to all operators. Makes sure that all responses are received
func (c *Initiator) SendToAll(method string, msg []byte, operators []*spec.Operator) (map[uint64][]byte, map[uint64]error) {
	errors := make(map[uint64]error, 0)
	resc := make(chan opReqResult, len(operators))
	for _, op := range operators {
		operator := c.Operators.ByID(op.ID)
		if operator == nil {
			errors[op.ID] = fmt.Errorf("operator ID: %d not found in operators list", op.ID)
		}
		go func() {
			res, err := c.SendAndCollect(*operator, method, msg)
			resc <- opReqResult{
				operatorID: operator.ID,
				err:        err,
				result:     res,
			}
		}()
	}
	responses := make(map[uint64][]byte)
	for i := 0; i < len(operators); i++ {
		res := <-resc
		if res.err != nil {
			errors[res.operatorID] = fmt.Errorf("operator ID: %d, %w", res.operatorID, res.err)
			continue
		}
		responses[res.operatorID] = res.result
	}
	return responses, errors
}

func ProcessError(err error) error {
	if strings.Contains(err.Error(), "context deadline exceeded") {
		return fmt.Errorf("the requested server is not responding, not a DKG endpoint: %w", err)
	}
	if strings.Contains(err.Error(), "no such host") {
		return fmt.Errorf("the requested server IP is not reachable: %w", err)
	}
	return err
}
