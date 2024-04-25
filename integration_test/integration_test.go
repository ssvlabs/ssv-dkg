package integration_test

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"strconv"
	"testing"
	"unsafe"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	cli_initiator "github.com/bloxapp/ssv-dkg/cli/initiator"
	cli_verify "github.com/bloxapp/ssv-dkg/cli/verify"
	"github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/initiator"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/utils/test_utils"
	"github.com/bloxapp/ssv-dkg/pkgs/validator"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

var (
	rootCert     = []string{"./certs/rootCA.crt"}
	operatorCert = "./certs/localhost.crt"
	operatorKey  = "./certs/localhost.key"
)

func TestInitHappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	servers, ops := createOperators(t, version)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	t.Run("test 4 operators init happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 7 operators init happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 10 operators init happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 13 operators init happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestResignHappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	servers, ops := createOperators(t, version)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	t.Run("test 4 operators resign happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "holesky", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = crypto.NewID()
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44}, wire.ConvertSignedProofsToSpec(proofs), "holesky", withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 7 operators resign happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = crypto.NewID()
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44, 55, 66, 77}, wire.ConvertSignedProofsToSpec(proofs), "holesky", withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 10 operators resign happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = crypto.NewID()
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, wire.ConvertSignedProofsToSpec(proofs), "holesky", withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	t.Run("test 13 operators resign happy flow", func(t *testing.T) {
		id := crypto.NewID()
		depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "mainnet", owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
		// re-sign
		id = crypto.NewID()
		depositData, ks, proofs, err = clnt.StartResigning(id, []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, wire.ConvertSignedProofsToSpec(proofs), "holesky", withdraw.Bytes(), owner, 0)
		require.NoError(t, err)
		err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkHappyFlows4Ops(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	servers, ops := createOperators(t, version)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 4 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})

	t.Run("test 4 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 4 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 4 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			args := []string{"resign", "--proofsFilePath", proofsFilePath, "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44", "--nonce", "10", "--clientCACertPath", "./certs/rootCA.crt"}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// validate resign results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(10)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkHappyFlows7Ops(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	servers, ops := createOperators(t, version)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 7 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 7 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 7 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 7 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			args := []string{"resign", "--proofsFilePath", proofsFilePath, "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77", "--nonce", "10", "--clientCACertPath", "./certs/rootCA.crt"}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// validate resign results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(10)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkHappyFlows10Ops(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	servers, ops := createOperators(t, version)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 10 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 10 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 10 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 10 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			args := []string{"resign", "--proofsFilePath", proofsFilePath, "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100", "--nonce", "10", "--clientCACertPath", "./certs/rootCA.crt"}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// validate resign results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(10)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestBulkHappyFlows13Ops(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	version := "test.version"
	servers, ops := createOperators(t, version)
	operators, err := json.Marshal(ops)
	require.NoError(t, err)
	RootCmd := &cobra.Command{
		Use:   "ssv-dkg",
		Short: "CLI for running Distributed Key Generation protocol",
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
		},
	}
	RootCmd.AddCommand(cli_initiator.StartDKG)
	RootCmd.AddCommand(cli_initiator.StartResigning)
	RootCmd.AddCommand(cli_verify.Verify)
	RootCmd.Short = "ssv-dkg-test"
	RootCmd.Version = version
	cli_initiator.StartDKG.Version = version
	cli_initiator.StartResigning.Version = version
	cli_verify.Verify.Version = version
	t.Run("test 13 operators 1 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "1", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 13 operators 10 validators bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "10", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	t.Run("test 13 operators 100 validator bulk happy flow", func(t *testing.T) {
		args := []string{"init", "--validators", "100", "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "1", "--clientCACertPath", "./certs/rootCA.crt"}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	})
	// validate results
	initCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	validators := []int{1, 10, 100}
	for i, c := range initCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(1)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	// re-sign
	t.Run("test 13 operators bulk resign", func(t *testing.T) {
		for i, c := range initCeremonies {
			proofsFilePath := "./output/" + c.Name() + "/proofs.json"
			if validators[i] == 1 {
				ceremonyDir, err := os.ReadDir("./output/" + c.Name())
				require.NoError(t, err)
				proofsFilePath = "./output/" + c.Name() + "/" + ceremonyDir[0].Name() + "/proofs.json"
			}
			args := []string{"resign", "--proofsFilePath", proofsFilePath, "--operatorsInfo", string(operators), "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--operatorIDs", "11,22,33,44,55,66,77,88,99,100,111,122,133", "--nonce", "10", "--clientCACertPath", "./certs/rootCA.crt"}
			RootCmd.SetArgs(args)
			err = RootCmd.Execute()
			require.NoError(t, err)
			resetFlags(RootCmd)
		}
	})
	// remove init ceremonies
	for _, c := range initCeremonies {
		err = os.RemoveAll("./output/" + c.Name())
		require.NoError(t, err)
	}
	// validate resign results
	resignCeremonies, err := os.ReadDir("./output")
	require.NoError(t, err)
	for i, c := range resignCeremonies {
		args := []string{"verify", "--ceremonyDir", "./output/" + c.Name(), "--validators", strconv.Itoa(validators[i]), "--withdrawAddress", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--owner", "0x81592c3de184a3e2c0dcb5a261bc107bfa91f494", "--nonce", strconv.Itoa(10)}
		RootCmd.SetArgs(args)
		err := RootCmd.Execute()
		require.NoError(t, err)
		resetFlags(RootCmd)
	}
	err = os.RemoveAll("./output/")
	require.NoError(t, err)
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestThreshold(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	servers, ops := createOperators(t, version)
	clnt, err := initiator.New(ops, logger, version, rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	t.Run("test 13 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		threshold, err := utils.GetThreshold([]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133})
		require.NoError(t, err)
		priviteKeys := []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey, servers[4].PrivKey, servers[5].PrivKey, servers[6].PrivKey, servers[7].PrivKey}
		require.Less(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 13, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid minimum threshold
		priviteKeys = []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey, servers[4].PrivKey, servers[5].PrivKey, servers[6].PrivKey, servers[7].PrivKey, servers[8].PrivKey}
		require.Equal(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 13, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 10 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		threshold, err := utils.GetThreshold([]uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100})
		require.NoError(t, err)
		priviteKeys := []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey, servers[4].PrivKey, servers[5].PrivKey}
		require.Less(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 10, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid minimum threshold
		priviteKeys = []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey, servers[4].PrivKey, servers[5].PrivKey, servers[6].PrivKey}
		require.Equal(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 10, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 7 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		threshold, err := utils.GetThreshold([]uint64{11, 22, 33, 44, 55, 66, 77})
		require.NoError(t, err)
		priviteKeys := []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey}
		require.Less(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 7, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid minimum threshold
		priviteKeys = []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey, servers[4].PrivKey}
		require.Equal(t, len(priviteKeys), threshold)
		err = testSharesData(ops, 7, priviteKeys, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	t.Run("test 4 operators threshold", func(t *testing.T) {
		id := crypto.NewID()
		_, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		err = testSharesData(ops, 4, []*rsa.PrivateKey{servers[0].PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "could not reconstruct a valid signature")
		// test valid threshold
		err = testSharesData(ops, 4, []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
		err = testSharesData(ops, 4, []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
		require.NoError(t, err)
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestUnhappyFlows(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	version := "test.version"
	servers, ops := createOperators(t, version)
	ops = append(ops, wire.OperatorCLI{Addr: servers[12].HttpSrv.URL, ID: 133, PubKey: &servers[12].PrivKey.PublicKey})
	ops = append(ops, wire.OperatorCLI{Addr: servers[12].HttpSrv.URL, ID: 0, PubKey: &servers[12].PrivKey.PublicKey})
	ops = append(ops, wire.OperatorCLI{Addr: servers[12].HttpSrv.URL, ID: 144, PubKey: &servers[12].PrivKey.PublicKey})
	ops = append(ops, wire.OperatorCLI{Addr: servers[12].HttpSrv.URL, ID: 155, PubKey: &servers[12].PrivKey.PublicKey})
	clnt, err := initiator.New(ops, logger, "test.version", rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	depositData, ks, _, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "mainnet", owner, 0)
	require.NoError(t, err)
	sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
	require.NoError(t, err)
	pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
	require.NoError(t, err)
	err = testSharesData(ops, 4, []*rsa.PrivateKey{servers[0].PrivKey, servers[1].PrivKey, servers[2].PrivKey, servers[3].PrivKey}, sharesDataSigned, pubkeyraw, owner, 0)
	require.NoError(t, err)
	err = crypto.ValidateDepositDataCLI(depositData, withdraw)
	require.NoError(t, err)
	marshalledKs, err := json.Marshal(ks)
	require.NotEmpty(t, marshalledKs)
	require.NoError(t, err)
	t.Run("test wrong operators shares order at SSV payload", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		_, ks, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133}, "mainnet", owner, 0)
		require.NoError(t, err)
		sharesDataSigned, err := hex.DecodeString(ks.Shares[0].Payload.SharesData[2:])
		require.NoError(t, err)
		pubkeyraw, err := hex.DecodeString(ks.Shares[0].Payload.PublicKey[2:])
		require.NoError(t, err)
		signatureOffset := phase0.SignatureLength
		pubKeysOffset := phase0.PublicKeyLength*13 + signatureOffset
		_ = utils.SplitBytes(sharesDataSigned[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
		encryptedKeys := utils.SplitBytes(sharesDataSigned[pubKeysOffset:], len(sharesDataSigned[pubKeysOffset:])/13)
		wrongOrderSharesData := make([]byte, 0)
		wrongOrderSharesData = append(wrongOrderSharesData, sharesDataSigned[:pubKeysOffset]...)
		for i := len(encryptedKeys) - 1; i >= 0; i-- {
			wrongOrderSharesData = append(wrongOrderSharesData, encryptedKeys[i]...)
		}
		err = testSharesData(ops, 13, []*rsa.PrivateKey{servers[12].PrivKey, servers[11].PrivKey, servers[10].PrivKey, servers[9].PrivKey, servers[8].PrivKey, servers[7].PrivKey, servers[6].PrivKey, servers[5].PrivKey, servers[4].PrivKey, servers[3].PrivKey, servers[2].PrivKey, servers[1].PrivKey, servers[0].PrivKey}, wrongOrderSharesData, pubkeyraw, owner, 0)
		require.ErrorContains(t, err, "shares order is incorrect")
	})
	t.Run("test same ID", func(t *testing.T) {
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "got init msg for existing instance")
	})
	t.Run("test wrong operator IDs", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{101, 66, 77, 88}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operator is not in given operator data list")
	})
	t.Run("test non 3f+1 operator set", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		// 0 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		// 1 op
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		// 2 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		// 3 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: < 4")
		// op with zero ID
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{0, 11, 22, 33}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operator ID cannot be 0")
		// 14 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133, 144}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: > 13")
		// 15 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88, 99, 100, 111, 122, 133, 144, 155}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "wrong operators len: > 13")
		// 5 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 6 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 8 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{11, 22, 33, 44, 55, 66, 77, 88}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 9 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 11 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
		// 12 ops
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "amount of operators should be 4,7,10,13")
	})
	t.Run("test out of order operators (i.e 3,2,4,1) ", func(t *testing.T) {
		withdraw := newEthAddress(t)
		owner := newEthAddress(t)
		id := crypto.NewID()
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 22, 44, 11}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 22, 44, 11, 100, 111, 122}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 22, 44, 11, 100, 111, 122, 99, 88, 77}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 22, 44, 11, 100, 111, 122, 99, 88, 77, 66, 55, 133}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators not unique or not ordered")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 33, 44, 11}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators ids should be unique in the list")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 22, 44, 22, 100, 111, 122, 99, 88, 77}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators ids should be unique in the list")
		_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{33, 22, 44, 11, 100, 111, 122, 99, 88, 77, 66, 55, 111}, "mainnet", owner, 0)
		require.ErrorContains(t, err, "operators ids should be unique in the list")
	})
	for _, srv := range servers {
		srv.HttpSrv.Close()
	}
}

func TestLargeOperatorIDs(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := wire.OperatorsCLI{}
	srv1 := test_utils.CreateTestOperator(t, 1100, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv1.HttpSrv.URL, ID: 1100, PubKey: &srv1.PrivKey.PublicKey})
	srv2 := test_utils.CreateTestOperator(t, 2222, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv2.HttpSrv.URL, ID: 2222, PubKey: &srv2.PrivKey.PublicKey})
	srv3 := test_utils.CreateTestOperator(t, 3300, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv3.HttpSrv.URL, ID: 3300, PubKey: &srv3.PrivKey.PublicKey})
	srv4 := test_utils.CreateTestOperator(t, 4444, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv4.HttpSrv.URL, ID: 4444, PubKey: &srv4.PrivKey.PublicKey})
	srv5 := test_utils.CreateTestOperator(t, 5555, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv5.HttpSrv.URL, ID: 5555, PubKey: &srv5.PrivKey.PublicKey})
	srv6 := test_utils.CreateTestOperator(t, 6666, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv6.HttpSrv.URL, ID: 6666, PubKey: &srv6.PrivKey.PublicKey})
	srv7 := test_utils.CreateTestOperator(t, 7777, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv7.HttpSrv.URL, ID: 7777, PubKey: &srv7.PrivKey.PublicKey})
	srv8 := test_utils.CreateTestOperator(t, 8888, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv8.HttpSrv.URL, ID: 8888, PubKey: &srv8.PrivKey.PublicKey})
	srv9 := test_utils.CreateTestOperator(t, 9999, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv9.HttpSrv.URL, ID: 9999, PubKey: &srv9.PrivKey.PublicKey})
	srv10 := test_utils.CreateTestOperator(t, 10000, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv10.HttpSrv.URL, ID: 10000, PubKey: &srv10.PrivKey.PublicKey})
	srv11 := test_utils.CreateTestOperator(t, 11111, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv11.HttpSrv.URL, ID: 11111, PubKey: &srv11.PrivKey.PublicKey})
	srv12 := test_utils.CreateTestOperator(t, 12222, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv12.HttpSrv.URL, ID: 12222, PubKey: &srv12.PrivKey.PublicKey})
	srv13 := test_utils.CreateTestOperator(t, 13333, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv13.HttpSrv.URL, ID: 13333, PubKey: &srv13.PrivKey.PublicKey})
	clnt, err := initiator.New(ops, logger, "test.version", rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	depositData, ks, proofs, err := clnt.StartDKG(id, withdraw.Bytes(), []uint64{1100, 2222, 3300, 4444, 5555, 6666, 7777, 8888, 9999, 10000, 11111, 12222, 13333}, "mainnet", owner, 0)
	require.NoError(t, err)
	err = validator.ValidateResults([]*wire.DepositDataCLI{depositData}, ks, [][]*wire.SignedProof{proofs}, 1, owner, 0, withdraw)
	require.NoError(t, err)
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
	srv5.HttpSrv.Close()
	srv6.HttpSrv.Close()
	srv7.HttpSrv.Close()
	srv8.HttpSrv.Close()
	srv9.HttpSrv.Close()
	srv10.HttpSrv.Close()
	srv11.HttpSrv.Close()
	srv12.HttpSrv.Close()
	srv13.HttpSrv.Close()
}

func TestWrongInitiatorVersion(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := wire.OperatorsCLI{}
	srv1 := test_utils.CreateTestOperator(t, 1, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey})
	srv2 := test_utils.CreateTestOperator(t, 2, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey})
	srv3 := test_utils.CreateTestOperator(t, 3, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey})
	srv4 := test_utils.CreateTestOperator(t, 4, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey})
	clnt, err := initiator.New(ops, logger, "v1.0.0", rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
	require.ErrorContains(t, err, "wrong version")
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func TestWrongOperatorVersion(t *testing.T) {
	err := logging.SetGlobalLogger("info", "capital", "console", nil)
	require.NoError(t, err)
	logger := zap.L().Named("integration-tests")
	ops := wire.OperatorsCLI{}
	srv1 := test_utils.CreateTestOperator(t, 1, "v1.0.0", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv1.HttpSrv.URL, ID: 1, PubKey: &srv1.PrivKey.PublicKey})
	srv2 := test_utils.CreateTestOperator(t, 2, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv2.HttpSrv.URL, ID: 2, PubKey: &srv2.PrivKey.PublicKey})
	srv3 := test_utils.CreateTestOperator(t, 3, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv3.HttpSrv.URL, ID: 3, PubKey: &srv3.PrivKey.PublicKey})
	srv4 := test_utils.CreateTestOperator(t, 4, "test.version", operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv4.HttpSrv.URL, ID: 4, PubKey: &srv4.PrivKey.PublicKey})
	clnt, err := initiator.New(ops, logger, "test.version", rootCert)
	require.NoError(t, err)
	withdraw := newEthAddress(t)
	owner := newEthAddress(t)
	id := crypto.NewID()
	_, _, _, err = clnt.StartDKG(id, withdraw.Bytes(), []uint64{1, 2, 3, 4}, "mainnet", owner, 0)
	require.ErrorContains(t, err, "wrong version")
	srv1.HttpSrv.Close()
	srv2.HttpSrv.Close()
	srv3.HttpSrv.Close()
	srv4.HttpSrv.Close()
}

func testSharesData(ops wire.OperatorsCLI, operatorCount int, keys []*rsa.PrivateKey, sharesData, validatorPublicKey []byte, owner common.Address, nonce uint16) error {
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := crypto.EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("shares data len is not correct")
	}
	signature := sharesData[:signatureOffset]
	msg := []byte("Hello")
	err := crypto.VerifyOwnerNonceSignature(signature, owner, validatorPublicKey, nonce)
	if err != nil {
		return err
	}
	_ = utils.SplitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := utils.SplitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	sigs2 := make(map[uint64][]byte)
	opsIDs := make([]uint64, 0)
	for i, enck := range encryptedKeys {
		if len(keys) <= i {
			continue
		}
		priv := keys[i]

		share, err := rsaencryption.DecodeKey(priv, enck)
		if err != nil {
			return err
		}
		secret := &bls.SecretKey{}
		err = secret.SetHexString(string(share))
		if err != nil {
			return err
		}
		// Find operator ID by PubKey
		var operatorID uint64
		for _, op := range ops {
			if bytes.Equal(priv.PublicKey.N.Bytes(), op.PubKey.N.Bytes()) {
				operatorID = op.ID
				break
			}
		}
		sig := secret.SignByte(msg)
		sigs2[operatorID] = sig.Serialize()

		// operators encoded shares should be ordered in increasing manner
		for _, op := range ops {
			if op.PubKey == &priv.PublicKey {
				opsIDs = append(opsIDs, op.ID)
			}
		}
	}
	// check if operators ordered correctly
	k := uint64(0)
	for _, i := range opsIDs {
		if i > k {
			k = i
		} else {
			return fmt.Errorf("shares order is incorrect")
		}
	}
	recon, err := ReconstructSignatures(sigs2)
	if err != nil {
		return err
	}
	err = VerifyReconstructedSignature(recon, validatorPublicKey, msg)
	if err != nil {
		return err
	}
	return nil
}

// ReconstructSignatures receives a map of user indexes and serialized bls.Sign.
// It then reconstructs the original threshold signature using lagrange interpolation
func ReconstructSignatures(signatures map[uint64][]byte) (*bls.Sign, error) {
	reconstructedSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for index, signature := range signatures {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", index))
		if err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		blsSig := bls.Sign{}

		err = blsSig.Deserialize(signature)
		if err != nil {
			return nil, err
		}
		sigVec = append(sigVec, blsSig)
	}
	err := reconstructedSig.Recover(sigVec, idVec)
	return &reconstructedSig, err
}

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey, msg []byte) error {
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(validatorPubKey); err != nil {
		return errors.Wrap(err, "could not deserialize validator pk")
	}
	// verify reconstructed sig
	if res := sig.VerifyByte(pk, msg); !res {
		return errors.New("could not reconstruct a valid signature")
	}
	return nil
}

func newEthAddress(t *testing.T) common.Address {
	privateKey, err := eth_crypto.GenerateKey()
	require.NoError(t, err)
	publicKey := privateKey.Public()
	publicKeyECDSA, ok := publicKey.(*ecdsa.PublicKey)
	require.True(t, ok)
	address := eth_crypto.PubkeyToAddress(*publicKeyECDSA)
	return address
}

func createOperators(t *testing.T, version string) ([]*test_utils.TestOperator, wire.OperatorsCLI) {
	var servers []*test_utils.TestOperator
	ops := wire.OperatorsCLI{}
	srv1 := test_utils.CreateTestOperator(t, 11, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv1.HttpSrv.URL, ID: 11, PubKey: &srv1.PrivKey.PublicKey})
	servers = append(servers, srv1)
	srv2 := test_utils.CreateTestOperator(t, 22, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv2.HttpSrv.URL, ID: 22, PubKey: &srv2.PrivKey.PublicKey})
	servers = append(servers, srv2)
	srv3 := test_utils.CreateTestOperator(t, 33, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv3.HttpSrv.URL, ID: 33, PubKey: &srv3.PrivKey.PublicKey})
	servers = append(servers, srv3)
	srv4 := test_utils.CreateTestOperator(t, 44, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv4.HttpSrv.URL, ID: 44, PubKey: &srv4.PrivKey.PublicKey})
	servers = append(servers, srv4)
	srv5 := test_utils.CreateTestOperator(t, 55, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv5.HttpSrv.URL, ID: 55, PubKey: &srv5.PrivKey.PublicKey})
	servers = append(servers, srv5)
	srv6 := test_utils.CreateTestOperator(t, 66, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv6.HttpSrv.URL, ID: 66, PubKey: &srv6.PrivKey.PublicKey})
	servers = append(servers, srv6)
	srv7 := test_utils.CreateTestOperator(t, 77, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv7.HttpSrv.URL, ID: 77, PubKey: &srv7.PrivKey.PublicKey})
	servers = append(servers, srv7)
	srv8 := test_utils.CreateTestOperator(t, 88, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv8.HttpSrv.URL, ID: 88, PubKey: &srv8.PrivKey.PublicKey})
	servers = append(servers, srv8)
	srv9 := test_utils.CreateTestOperator(t, 99, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv9.HttpSrv.URL, ID: 99, PubKey: &srv9.PrivKey.PublicKey})
	servers = append(servers, srv9)
	srv10 := test_utils.CreateTestOperator(t, 100, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv10.HttpSrv.URL, ID: 100, PubKey: &srv10.PrivKey.PublicKey})
	servers = append(servers, srv10)
	srv11 := test_utils.CreateTestOperator(t, 111, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv11.HttpSrv.URL, ID: 111, PubKey: &srv11.PrivKey.PublicKey})
	servers = append(servers, srv11)
	srv12 := test_utils.CreateTestOperator(t, 122, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv12.HttpSrv.URL, ID: 122, PubKey: &srv12.PrivKey.PublicKey})
	servers = append(servers, srv12)
	srv13 := test_utils.CreateTestOperator(t, 133, version, operatorCert, operatorKey)
	ops = append(ops, wire.OperatorCLI{Addr: srv13.HttpSrv.URL, ID: 133, PubKey: &srv13.PrivKey.PublicKey})
	servers = append(servers, srv13)

	return servers, ops
}

func resetFlags(cmd *cobra.Command) {
	cmd.Flags().VisitAll(func(flag *pflag.Flag) {
		if flag.Value.Type() == "stringSlice" {
			value := reflect.ValueOf(flag.Value).Elem().FieldByName("value")
			ptr := (*[]string)(unsafe.Pointer(value.Pointer()))
			*ptr = make([]string, 0)
		}
	})
	for _, cmd := range cmd.Commands() {
		resetFlags(cmd)
	}
}
