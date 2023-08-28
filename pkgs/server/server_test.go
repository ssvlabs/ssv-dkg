package server

import (
	"fmt"
	"testing"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/wire"
	"github.com/ethereum/go-ethereum/common"
	"github.com/imroc/req/v3"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const exmaplePath = "../../examples/"

func TestGeneralRateLimit(t *testing.T) {
	pk, err := load.EncryptedPrivateKey(exmaplePath+"server"+fmt.Sprintf("%v", 1)+"/encrypted_private_key.json", "12345678")
	require.NoError(t, err)
	srv := New(pk)
	eg := errgroup.Group{}
	eg.Go(func() error {
		err := srv.Start(3030)
		require.NoError(t, err)
		return err
	})

	ops := make(map[uint64]client.Operator)
	ops[1] = client.Operator{"http://localhost:3030", 1, &srv.State.privateKey.PublicKey}

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
		WithdrawalCredentials: []byte("0100000000000000000000001d2f14d2dffee594b4093d42e4bc1b0ea55e8aa7"),
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
	// type response struct {
	// 	Data []byte
	// 	Err  error
	// }
	resc := make(chan error)
	// Send requests
	for i := 0; i < 1000; i++ {
		go func() {
			res, err := r.Post(fmt.Sprintf("%v/%v", "http://localhost:3030", "init"))
			require.NoError(t, err)
			if res.Status != "200 OK" {
				t.Log(res.Status)
				resc <- fmt.Errorf("rate limit")
			}

		}()
	}
	for err := range resc {
		require.NoError(t, err)
	}
}
