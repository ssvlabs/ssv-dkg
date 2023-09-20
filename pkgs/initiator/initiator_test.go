package initiator

import (
	"bytes"
	"crypto/rsa"
	"encoding/hex"
	"fmt"
	"math/big"
	"net/http/httptest"
	"sync"
	"testing"
	"time"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/bloxapp/ssv/logging"
	"github.com/bloxapp/ssv/utils/rsaencryption"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/go-chi/chi/v5"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/require"
	"go.uber.org/zap"

	ourcrypto "github.com/bloxapp/ssv-dkg/pkgs/crypto"
	"github.com/bloxapp/ssv-dkg/pkgs/dkg"
	operator "github.com/bloxapp/ssv-dkg/pkgs/operator"
)

// TODO: use mocks instead of servers
type testOperator struct {
	id      uint64
	privKey *rsa.PrivateKey
	srv     *httptest.Server
}

func TestOperatorMisbehave(t *testing.T) {
	if err := logging.SetGlobalLogger("info", "capital", "console", nil); err != nil {
		panic(err)
	}
	logger := zap.L().Named("operator-tests")
	ops := make(map[uint64]Operator)
	srv1 := CreateTestOperator(t, 1)
	srv2 := CreateTestOperator(t, 2)
	srv3 := CreateTestOperator(t, 3)
	srv4 := CreateTestOperator(t, 4)
	ops[1] = Operator{srv1.srv.URL, 1, &srv1.privKey.PublicKey}
	ops[2] = Operator{srv2.srv.URL, 2, &srv2.privKey.PublicKey}
	ops[3] = Operator{srv3.srv.URL, 3, &srv3.privKey.PublicKey}
	ops[4] = Operator{srv4.srv.URL, 4, &srv4.privKey.PublicKey}
	_, pv, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(pv))
	require.NoError(t, err)
	withdraw := common.HexToAddress("0x0000000000000000000000000000000000000009")
	owner := common.HexToAddress("0x0000000000000000000000000000000000000007")
	t.Run("happy flow", func(t *testing.T) {
		initiator := New(priv, ops, logger)
		depositData, keyshares, err := initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.NoError(t, err)
		testSharesData(t, ops, []*rsa.PrivateKey{srv1.privKey, srv2.privKey, srv3.privKey, srv4.privKey}, keyshares, owner, 0)
		testDepositData(t, depositData, withdraw.Bytes(), owner, 0)
	})
	t.Run("test wrong amount of opeators < 4", func(t *testing.T) {
		initiator := New(priv, ops, logger)
		_, _, err = initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "minimum supported amount of operators is 4")
	})
	t.Run("test wrong amount of opeators > 13", func(t *testing.T) {
		initiator := New(priv, ops, logger)
		_, _, err = initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "maximum supported amount of operators is 13")
	})
	t.Run("test opeators not unique", func(t *testing.T) {
		initiator := New(priv, ops, logger)
		_, _, err = initiator.StartDKG(withdraw.Bytes(), []uint64{1, 2, 3, 4, 5, 6, 7, 7, 9, 10, 11, 12, 12}, [4]byte{0, 0, 0, 0}, "mainnnet", owner, 0)
		require.ErrorContains(t, err, "operators ids should be unique in the list")
	})

	srv1.srv.Close()
	srv2.srv.Close()
	srv3.srv.Close()
	srv4.srv.Close()
}

func CreateTestOperator(t *testing.T, id uint64) *testOperator {
	if err := logging.SetGlobalLogger("info", "capital", "console", nil); err != nil {
		panic(err)
	}
	logger := zap.L().Named("operator-tests")
	_, privBytes, err := rsaencryption.GenerateKeys()
	require.NoError(t, err)
	priv, err := rsaencryption.ConvertPemToPrivateKey(string(privBytes))
	require.NoError(t, err)
	r := chi.NewRouter()
	swtch := &operator.Switch{
		Logger:           logger,
		Mtx:              sync.RWMutex{},
		InstanceInitTime: make(map[operator.InstanceID]time.Time, operator.MaxInstances),
		Instances:        make(map[operator.InstanceID]operator.Instance, operator.MaxInstances),
		PrivateKey:       priv,
	}

	lg := logrus.New()
	lg.SetLevel(logrus.DebugLevel)
	s := &operator.Server{
		Logger: logger,
		Router: r,
		State:  swtch,
	}
	operator.RegisterRoutes(s)
	sTest := httptest.NewServer(s.Router)
	return &testOperator{
		id:      id,
		privKey: priv,
		srv:     sTest,
	}
}

func testSharesData(t *testing.T, ops map[uint64]Operator, keys []*rsa.PrivateKey, ks *KeyShares, owner common.Address, nonce uint16) {
	sharesData, err := hex.DecodeString(ks.Payload.Readable.Shares[2:])
	require.NoError(t, err)
	validatorPublicKey, err := hex.DecodeString(ks.Payload.Readable.PublicKey[2:])
	require.NoError(t, err)

	operatorCount := len(keys)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := encryptedKeyLength*operatorCount + pubKeysOffset
	require.Len(t, sharesData, sharesExpectedLength)
	signature := sharesData[:signatureOffset]
	msg := []byte("Hello")
	require.NoError(t, ourcrypto.VerifyOwnerNoceSignature(signature, owner, validatorPublicKey, nonce))
	_ = splitBytes(sharesData[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	encryptedKeys := splitBytes(sharesData[pubKeysOffset:], len(sharesData[pubKeysOffset:])/operatorCount)
	sigs2 := make(map[uint64][]byte)
	for i, enck := range encryptedKeys {
		priv := keys[i]
		share, err := rsaencryption.DecodeKey(priv, enck)
		require.NoError(t, err)
		secret := &bls.SecretKey{}
		require.NoError(t, secret.SetHexString(string(share)))
		// Find operator ID by PubKey
		var operatorID uint64
		for id, op := range ops {
			if bytes.Equal(priv.PublicKey.N.Bytes(), op.PubKey.N.Bytes()) {
				operatorID = id
			}
		}
		sig := secret.SignByte(msg)
		sigs2[operatorID] = sig.Serialize()
	}
	recon, err := ReconstructSignatures(sigs2)
	require.NoError(t, err)
	require.NoError(t, VerifyReconstructedSignature(recon, validatorPublicKey, msg))
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

func VerifyReconstructedSignature(sig *bls.Sign, validatorPubKey []byte, msg []byte) error {
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

func splitBytes(buf []byte, lim int) [][]byte {
	var chunk []byte
	chunks := make([][]byte, 0, len(buf)/lim+1)
	for len(buf) >= lim {
		chunk, buf = buf[:lim], buf[lim:]
		chunks = append(chunks, chunk)
	}
	if len(buf) > 0 {
		chunks = append(chunks, buf[:])
	}
	return chunks
}

func testDepositData(t *testing.T, depsitDataJson *DepositDataJson, withdrawCred []byte, owner common.Address, nonce uint16) {
	require.True(t, bytes.Equal(ourcrypto.WithdrawalCredentialsHash(withdrawCred), hexutil.MustDecode("0x"+depsitDataJson.WithdrawalCredentials)))
	masterSig := &bls.Sign{}
	require.NoError(t, masterSig.DeserializeHexStr(depsitDataJson.Signature))
	valdatorPubKey := &bls.PublicKey{}
	require.NoError(t, valdatorPubKey.DeserializeHexStr(depsitDataJson.PubKey))

	// Check root
	var fork [4]byte
	copy(fork[:], hexutil.MustDecode("0x"+depsitDataJson.ForkVersion))
	depositDataRoot, err := ourcrypto.DepositDataRoot(withdrawCred, valdatorPubKey, dkg.GetNetworkByFork(fork), MaxEffectiveBalanceInGwei)
	require.NoError(t, err)
	res := masterSig.VerifyByte(valdatorPubKey, depositDataRoot[:])
	require.True(t, res)
	depositData, _, err := ourcrypto.DepositData(masterSig.Serialize(), withdrawCred, valdatorPubKey.Serialize(), dkg.GetNetworkByFork(fork), MaxEffectiveBalanceInGwei)
	require.NoError(t, err)
	res, err = ourcrypto.VerifyDepositData(depositData, dkg.GetNetworkByFork(fork))
	require.NoError(t, err)
	require.True(t, res)
	depositMsg := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                MaxEffectiveBalanceInGwei,
	}
	copy(depositMsg.PublicKey[:], depositData.PublicKey[:])
	depositMsgRoot, _ := depositMsg.HashTreeRoot()
	require.True(t, bytes.Equal(depositMsgRoot[:], hexutil.MustDecode("0x"+depsitDataJson.DepositMessageRoot)))
}

func generateOperators(ids []uint64) Operators {
	m := make(map[uint64]Operator)
	for _, i := range ids {
		m[i] = Operator{
			Addr: "",
			ID:   i,
			PubKey: &rsa.PublicKey{
				N: big.NewInt(1),
				E: 0,
			},
		}
	}

	return m
}

func TestValidateDKGParams(t *testing.T) {

	ops_1_13 := generateOperators([]uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13})
	ops_not_serial := generateOperators([]uint64{1, 15, 3, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13})

	tests := []struct {
		name    string
		ids     []uint64
		ops     Operators
		wantErr bool
		errMsg  string
	}{
		{
			name:    "less than 4 operators",
			ids:     []uint64{1, 2, 3},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "minimum supported amount of operators is 4",
		},
		{
			name:    "more than 13 operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14},
			ops:     nil, // doesn't matter should fail before
			wantErr: true,
			errMsg:  "maximum supported amount of operators is 13",
		},
		{
			name:    "duplicate operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 12},
			ops:     ops_1_13,
			wantErr: true,
			errMsg:  "operators ids should be unique in the list",
		},
		{
			name:    "valid operators",
			ids:     []uint64{1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13},
			ops:     ops_1_13,
			wantErr: false,
		},
		{
			name:    "other valid operators",
			ids:     []uint64{1, 15, 3, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13},
			ops:     ops_not_serial,
			wantErr: false,
		},
		{
			name:    "op not in list",
			ids:     []uint64{1, 15, 21, 41, 5, 28, 7, 52, 9, 10, 104, 200, 13},
			ops:     ops_not_serial,
			wantErr: true,
			errMsg:  "operator is not in given operator data list",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res, err := validatedOperatorData(tt.ids, tt.ops)
			if tt.wantErr {
				if err == nil {
					t.Errorf("expected error but got none")
				} else if err.Error() != tt.errMsg {
					t.Errorf("expected error message %q but got %q", tt.errMsg, err.Error())
				}
			} else if err != nil {
				t.Errorf("unexpected error: %v", err)
			} else {

				// verify list is ok
				need := len(tt.ids)
			verLoop:
				for _, id := range tt.ids {
					for _, op := range res {
						if op.ID == id {
							need--
							continue verLoop
						}
					}
				}

				require.Equal(t, need, 0)
			}
		})
	}
}
