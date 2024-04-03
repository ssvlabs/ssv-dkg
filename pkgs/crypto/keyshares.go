package crypto

import (
	"bytes"
	"encoding/hex"
	"fmt"
	"sort"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/ethereum/go-ethereum/common"
	"github.com/herumi/bls-eth-go-binary/bls"

	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
)

func ValidateKeysharesCLI(ks *wire.KeySharesCLI, operators []*wire.Operator, owner [20]byte, nonce uint64, valPub string) error {
	if ks.CreatedAt.String() == "" {
		return fmt.Errorf("keyshares creation time is empty")
	}
	// make sure operators are sorted by ID
	sorted := sort.SliceIsSorted(ks.Shares[0].Payload.OperatorIDs, func(p, q int) bool {
		return ks.Shares[0].Payload.OperatorIDs[p] < ks.Shares[0].Payload.OperatorIDs[q]
	})
	if !sorted {
		return fmt.Errorf("slice is not sorted")
	}
	// 1. check operators at json
	for i, op := range ks.Shares[0].Operators {
		if op.ID != operators[i].ID || !bytes.Equal(op.PubKey, operators[i].PubKey) {
			return fmt.Errorf("incorrect keyshares operators")
		}
	}
	// 2. check owner address is correct
	if common.HexToAddress(ks.Shares[0].OwnerAddress) != owner {
		return fmt.Errorf("incorrect keyshares owner")
	}
	// 3. check nonce is correct
	if ks.Shares[0].OwnerNonce != nonce {
		return fmt.Errorf("incorrect keyshares nonce")
	}
	// 4. check validator public key
	validatorPublicKey, err := hex.DecodeString(strings.TrimPrefix(ks.Shares[0].PublicKey, "0x"))
	if err != nil {
		return fmt.Errorf("cant decode validator pub key %w", err)
	}
	if "0x"+valPub != ks.Shares[0].PublicKey {
		return fmt.Errorf("incorrect keyshares validator pub key")
	}
	// 5. check operator IDs
	for i, op := range operators {
		if ks.Shares[0].Payload.OperatorIDs[i] != op.ID {
			return fmt.Errorf("incorrect keyshares operator IDs")
		}
	}
	// 6. check validator public key at payload
	if "0x"+valPub != ks.Shares[0].Payload.PublicKey {
		return fmt.Errorf("incorrect keyshares payload validator pub key")
	}
	// 7. check encrypted shares data
	sharesData, err := hex.DecodeString(strings.TrimPrefix(ks.Shares[0].Payload.SharesData, "0x"))
	if err != nil {
		return fmt.Errorf("cant decode enc shares %w", err)
	}
	operatorCount := len(operators)
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*operatorCount + signatureOffset
	sharesExpectedLength := EncryptedKeyLength*operatorCount + pubKeysOffset
	if len(sharesData) != sharesExpectedLength {
		return fmt.Errorf("shares data len is not correct")
	}
	signature := sharesData[:signatureOffset]
	err = VerifyOwnerNonceSignature(signature, owner, validatorPublicKey, uint16(ks.Shares[0].OwnerNonce))
	if err != nil {
		return fmt.Errorf("owner+nonce signature is invalid at keyshares json %w", err)
	}
	// 8. reconstruct validator pub key from shares pub keys
	if err := VerifyValidatorAtSharesData(ks.Shares[0].Payload.OperatorIDs, sharesData, validatorPublicKey); err != nil {
		return err
	}
	return nil
}

func VerifyValidatorAtSharesData(ids []uint64, keyShares, expValPubKey []byte) error {
	// Verify that IDs are unique and ordered.
	if !sort.SliceIsSorted(ids, func(i, j int) bool { return ids[i] < ids[j] }) {
		return fmt.Errorf("operators not ordered")
	}
	for i := 0; i < len(ids)-1; i++ {
		if ids[i] == ids[i+1] {
			return fmt.Errorf("operators not unique")
		}
	}

	pubKeyOffset := phase0.PublicKeyLength * len(ids)
	pubKeysSigOffset := pubKeyOffset + phase0.SignatureLength
	sharesExpectedLength := EncryptedKeyLength*len(ids) + pubKeysSigOffset
	if len(keyShares) != sharesExpectedLength {
		return fmt.Errorf("GetSecretShareFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	pubKeys := utils.SplitBytes(keyShares[phase0.SignatureLength:pubKeysSigOffset], phase0.PublicKeyLength)
	if len(pubKeys) != len(ids) {
		return fmt.Errorf("GetSecretShareFromSharesData: amount of public keys at keyshares slice is wrong: %d", len(pubKeys))
	}
	var sharePublicKeys []*bls.PublicKey
	for i := 0; i < len(ids); i++ {
		// find share pub key

		publicKey := &bls.PublicKey{}
		err := publicKey.Deserialize(pubKeys[i])
		if err != nil {
			return fmt.Errorf("GetSecretShareFromSharesData: cant deserialize public key at keyshares slice: %d", len(pubKeys))
		}
		sharePublicKeys = append(sharePublicKeys, publicKey)
	}
	validatorRecoveredPK, err := RecoverValidatorPublicKey(ids, sharePublicKeys)
	if err != nil {
		return fmt.Errorf("failed to recover validator public key from shares data: %w", err)
	}
	validatorRecoveredPKBytes := validatorRecoveredPK.Serialize()
	if !bytes.Equal(expValPubKey, validatorRecoveredPKBytes) {
		return fmt.Errorf("validator public key recovered from shares is different: exp %x, got %x", expValPubKey, validatorRecoveredPKBytes)
	}
	return nil
}
