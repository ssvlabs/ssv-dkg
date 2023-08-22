package client_test

import (
	"fmt"
	"testing"

	"github.com/bloxapp/ssv-dkg-tool/pkgs/client"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/client/test_server"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg-tool/pkgs/load"
	"github.com/ethereum/go-ethereum/common"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"golang.org/x/sync/errgroup"
)

const operatorsMetaData = `[
	{
	  "id": 1,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBMUFNUGUxaDd0UzJXUU1nTUVHKysKOEVVS3Z0NTFkd1E1bnlkNGd5TlEvampsZDRvRjRyS25nZTExQTNOcmVLT1hSR0dobmpueWpSU2JhM3AraDNMVwpWZHJzS2FJd051bU5yNzNiN01iZjVSL0IxOWo0MnZvZFJMeEFpcXE0My9XTXhYWjdVL3ZuQ1RRMUVTckVyOC9sCmpNMm9qY2lXb3F0WG55SENNYVRqQ1dHRWFBelRTditMOTVIOS9nZmVBcEtJa1NUbUNxUXdUQ2FzTnB4d3g3SU8KUnZuUFkrYWFMcjFVNi83M1BtTU9MVE0ySkpveEEwQTdJNSt4enExYjZwb2R3bCtpZ1FkQ2hKNTJYVWZaVkJreApQM2owc1lhU243c1JoT0VZRk1CWHJjRTh4bnpvc0Zmc0xBeCtjQTRsbEgzU3dad2p4azRaenVCOHJoQUw2enJ3Cm5RSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3030"
	},
	{
	  "id": 2,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdThmeS9Ia2VwZW5kYmVYRzl6c0sKUk9XRG9ZUnY0MFBmdHc2TnhCQ1phYzlsRGxHcFpmdHoxMjM1Q3BKc0RsUjYwNWpGTmFCdzZQN1JBNjhJZVhhbApqU2ZwcTFkQU1CZXpoNG93NmcwYkIrcVpJc1JMdHhUUnV2SGM5clUwLzBVQmJSYVhwc0poZHYwL2syU0RzeHRmCm9ZMEJ1Q2RQK2pYc1RCWlh0TUl6NVl0MmZYU3lWSG1zZElzeEFkN04zR0xWcVR0NmVCUXFiOHRXMnVqU0h0MGwKeENyQkw1eFp1bkZpWFJmVElGVGN5bjU2L0llSU50OVdyQXZXdmdKd2F5VUtLVnpycWJxVVp2SUVPdG9DMUVuRgplMVJRdXhVR1BYN21vMnc0QlZvYWRqcTJPVzFBYWxlQ1ppV2hERU8xT2ZwUXV0cDYrL0dqZHR2eGFSdEdjUFgwClZ3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3031"
	},
	{
	  "id": 3,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBdFlkU1B5b1ZwaVlCaytKaTd5TGYKdTlqcHRITWpqOEIxV2tqUjM4eFpZUTRPQXhWOEY0aSt0YTlGQ1JWK1p4QklGU2tPTWJZRTJ4QkJ3dkEwTVMzZQpQblBHWElqS2lxVlYzT1B5QWF3UC9Ia2FoSktwNmltRldlVGh1aXJoMnpEYnRsblpRY0lNUUhEeEhJTnhmVVFqCndjMVY5aHpsYWZkVUgvanAzQTVNaUFFSHlEcWRUeUZzc2tKRHdoaXNlZ0lCVnhpU0xqS2YvVXA2QytnWjhjYzUKTjdkbllmMGpHRnNDR2xQUVlvZHZzTGlvbDFvSzVZTXlOUVhLbFhSY1hSR1UzYlNVWDdGMGtDS2U2RFNwQkRDRwp1UW9Qck16UmJBRGpUY0lKTHVxOWlvOXJXQXdxQVhMNTd5YnpkRk9mUkpYMkZ3bzk1RWJObVhzblFHeHk4ZWpLCjN3SURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3032"
	},
	{
	  "id": 4,
	  "public_key": "LS0tLS1CRUdJTiBSU0EgUFVCTElDIEtFWS0tLS0tCk1JSUJJakFOQmdrcWhraUc5dzBCQVFFRkFBT0NBUThBTUlJQkNnS0NBUUVBd0FJcEdQTUwvdGtoOWZmTWsrYk0KdlN6NVUvUWpRNjJJOEpKSGlYR0dEcGYveEZoaEt0UTQ0a1JrNGpjQURZb1IyWm96ZE13S0ExYjljeEdVRlRTMQpCL1Y0NzRBQnU0UW1xUUtXWVdid2VwakxmQml3dGZGQm9KWFBTWEZ0VGdaWnVTNFRXM0JodzJHbzRrRGNEQVlCCjZNdEl2RjFkcXJ0NjE2K2xDUlhkRzlCNVRTcmRyanBqNWx3QmxUam0rMEdUdDA0K210WVlFZlVrcmtnbGJxM1EKZ3ZoYTB3eVhnb2Q3c2xsMkJ5ZU8ydVlnTG5KbE9CK0Fxd3M3dThtcGdTa01TQk9DNGRKSUJXdmJ1SDZtUGVDRgo3Z0tGNFRqUm4yWEZFVFpDQVdCRENWSmRVMnV4ZVpvamMvd0dZUkxSanVCdnBveFF2Yjl3bjFLL3IvMzFSNWowCnNRSURBUUFCCi0tLS0tRU5EIFJTQSBQVUJMSUMgS0VZLS0tLS0K",
	  "ip": "http://localhost:3033"
	}
  ]`

const exmaplePath = "../../examples/"

func CreateTestServer(t *testing.T, id uint64) *test_server.Server {
	pk, err := load.PrivateKey(exmaplePath + "server" + fmt.Sprintf("%v", id) + "/key")
	require.NoError(t, err)
	srv := test_server.New(pk, false)
	return srv
}

func CreateTestServerRandomKey(t *testing.T, id uint64) *test_server.Server {
	priv, _, err := crypto.GenerateKeys()
	require.NoError(t, err)
	srv := test_server.New(priv, false)
	return srv
}

func CreateEveTestServer(t *testing.T, id uint64) *test_server.Server {
	pk, err := load.PrivateKey(exmaplePath + "server" + fmt.Sprintf("%v", id) + "/key")
	require.NoError(t, err)
	srv := test_server.New(pk, true)
	return srv
}

func TestHappyFlow(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	srv1 := CreateTestServer(t, 1)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

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

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	err = clnt.StartDKG([]byte("0100000000000000000000001d2f14d2dffee594b4093d42e4bc1b0ea55e8aa7"), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000007").Bytes()), 0, false)
	require.NoError(t, err)

}

func TestWrongServerKey(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	srv1 := CreateTestServerRandomKey(t, 1)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

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

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	err = clnt.StartDKG([]byte("0100000000000000000000001d2f14d2dffee594b4093d42e4bc1b0ea55e8aa7"), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000007").Bytes()), 0, false)
	require.Error(t, err)
}

func TestWrongPartialSignatures(t *testing.T) {
	logger := logrus.NewEntry(logrus.New())

	logger.Infof("Starting intg test")

	srv1 := CreateEveTestServer(t, 1)
	srv2 := CreateTestServer(t, 2)
	srv3 := CreateTestServer(t, 3)
	srv4 := CreateTestServer(t, 4)

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

	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)

	clnt := client.New(opmap)

	logger.Infof("Client created")
	logger.Infof("Client Starting dkg")
	err = clnt.StartDKG([]byte("0100000000000000000000001d2f14d2dffee594b4093d42e4bc1b0ea55e8aa7"), []uint64{1, 2, 3, 4}, 3, [4]byte{0, 0, 0, 0}, "mainnnet", [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000007").Bytes()), 0, false)
	require.Error(t, err)
}

func TestWrongThreshold(t *testing.T) {
	opmap, err := load.LoadOperatorsJson([]byte(operatorsMetaData))
	require.NoError(t, err)
	clnt := client.New(opmap)
	err = clnt.StartDKG([]byte("0100000000000000000000001d2f14d2dffee594b4093d42e4bc1b0ea55e8aa7"), []uint64{1, 2, 3, 4}, 10, [4]byte{0, 0, 0, 0}, "mainnnet", [20]byte(common.HexToAddress("0x0000000000000000000000000000000000000007").Bytes()), 0, false)
	require.Error(t, err)
}
