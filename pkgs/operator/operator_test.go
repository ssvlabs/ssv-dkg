package operator

import (
	"fmt"
	"io"
	"sync"
	"testing"
	"time"

	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/load"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/ethereum/go-ethereum/common"
	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const exmaplePath = "../../examples/"

func TestRateLimit(t *testing.T) {
	pk, err := load.EncryptedPrivateKey(exmaplePath+"operator"+fmt.Sprintf("%v", 1)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	srv := New(pk)
	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv.Start(3030)
	})
	t.Run("test init route rate limit", func(t *testing.T) {
		ops := make(map[uint64]initiator.Operator)
		ops[1] = initiator.Operator{"http://localhost:3030", 1, &srv.State.PrivateKey.PublicKey}

		parts := make([]*wire.Operator, 0, 0)
		for _, id := range []uint64{1} {
			op, ok := ops[id]
			if !ok {
				t.Fatalf("no op")
			}
			pkBytes, err := crypto.EncodePublicKey(op.PubKey)
			if err != nil {
				require.NoError(t, err)
			}
			parts = append(parts, &wire.Operator{
				ID:     op.ID,
				PubKey: pkBytes,
			})
		}

		init := &wire.Init{
			Operators:             parts,
			T:                     3,
			WithdrawalCredentials: common.HexToAddress("0x0000000000000000000000000000000000000009").Bytes(),
			Fork:                  [4]byte{0, 0, 0, 0},
			Owner:                 common.HexToAddress("0x0000000000000000000000000000000000000007"),
			Nonce:                 0,
		}
		sszinit, err := init.MarshalSSZ()
		require.NoError(t, err)

		ts := &wire.Transport{
			Type:       wire.InitMessageType,
			Identifier: [24]byte{},
			Data:       sszinit,
		}

		tsssz, err := ts.MarshalSSZ()
		require.NoError(t, err)

		client := req.C()
		r := client.R()

		r.SetBodyBytes(tsssz)

		// Send requests
		errChan := make(chan []byte)
		time.Sleep(time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer close(errChan)
			defer wg.Done()
			for i := 0; i < 100; i++ {
				res, err := r.Post(fmt.Sprintf("%v/%v", "http://localhost:3030", "init"))
				require.NoError(t, err)
				if res.Status == "429 Too Many Requests" {
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					errChan <- b
				}
			}
		}()
		for errResp := range errChan {
			require.NotEmpty(t, errResp)
			require.Equal(t, ErrTooManyDKGRequests, string(errResp))
		}
		wg.Wait()
	})
	t.Run("test general rate limit", func(t *testing.T) {
		client := req.C()
		r := client.R()

		r.SetBodyBytes([]byte{})

		// Send requests
		errChan := make(chan []byte)
		time.Sleep(time.Second)
		var wg sync.WaitGroup
		wg.Add(1)
		go func() {
			defer close(errChan)
			defer wg.Done()
			for i := 0; i < 1000; i++ {
				res, err := r.Post(fmt.Sprintf("%v/%v", "http://localhost:3030", "dkg"))
				require.NoError(t, err)
				if res.Status == "429 Too Many Requests" {
					b, err := io.ReadAll(res.Body)
					require.NoError(t, err)
					errChan <- b
				}
			}
		}()
		for errResp := range errChan {
			require.NotEmpty(t, errResp)
			require.Equal(t, ErrTooManyOperatorRequests, string(errResp))
		}
		wg.Wait()
	})
	srv.HttpServer.Close()
}
