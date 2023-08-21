package integration

import (
	"fmt"
	"testing"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/server"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const exmaplePath = "../examples/"

func CreateServer(t *testing.T, id uint64) *server.Server {
	pk, err := load.PrivateKey(exmaplePath + "server" + fmt.Sprintf("%v", id) + "/key")
	require.NoError(t, err)
	srv := server.New(pk)

	return srv
}

func TestEverything(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	srv1 := CreateServer(t, 1)
	srv2 := CreateServer(t, 2)
	srv3 := CreateServer(t, 3)
	srv4 := CreateServer(t, 4)

	logger.Infof("Servers created")

	eg := errgroup.Group{}
	eg.Go(func() error {
		return srv1.Start(3030)
	})
	eg.Go(func() error {
		return srv2.Start(3031)
	})
	eg.Go(func() error {
		return srv3.Start(3032)
	})
	eg.Go(func() error {
		return srv4.Start(3033)
	})

	logger.Infof("Servers Started")

	ops, err := load.Operators(exmaplePath + "operators_integration.csv")
	require.NoError(t, err)

	clnt := client.New(ops)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	err = clnt.StartDKG([]byte("0100000000000000000000001d2f14d2dffee594b4093d42e4bc1b0ea55e8aa7"), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000007").Bytes()), 0)

	require.NoError(t, err)

}
