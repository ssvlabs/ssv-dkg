package crypto

import (
	"bytes"
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/sha512"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unicode"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	"github.com/drand/kyber"
	kyber_bls12381 "github.com/drand/kyber-bls12381"
	"github.com/drand/kyber/share"
	drand_dkg "github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/google/uuid"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"

	e2m_core "github.com/bloxapp/eth2-key-manager/core"
	e2m_deposit "github.com/bloxapp/eth2-key-manager/eth1_deposit"
	"github.com/bloxapp/ssv-dkg/pkgs/utils"
	"github.com/bloxapp/ssv-dkg/pkgs/wire"
	"github.com/bloxapp/ssv/utils/rsaencryption"
)

const (
	// b64 encrypted key length is 256
	EncryptedKeyLength = 256
	// Signature len
	SignatureLength = 256
	// BLSWithdrawalPrefixByte is the BLS withdrawal prefix
	BLSWithdrawalPrefixByte  = byte(0)
	ETH1WithdrawalPrefixByte = byte(1)
)

func init() {
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)
}

// GenerateKeys creates a random RSA key pair
func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		return nil, nil, err
	}

	return pv, &pv.PublicKey, nil

}

// SignRSA create a RSA signature for incoming bytes
func SignRSA(sk *rsa.PrivateKey, byts []byte) ([]byte, error) {
	r := sha256.Sum256(byts)
	return sk.Sign(rand.Reader, r[:], &rsa.PSSOptions{
		SaltLength: rsa.PSSSaltLengthAuto,
		Hash:       crypto.SHA256,
	})
}

// Encrypt with secret key (base64) the bytes, return the encrypted key string
func Encrypt(pk *rsa.PublicKey, plainText []byte) ([]byte, error) {
	encrypted, err := rsa.EncryptPKCS1v15(rand.Reader, pk, plainText)
	if err != nil {
		return nil, err
	}
	return encrypted, nil
}

// VerifyRSA verifies RSA signature for incoming message
func VerifyRSA(pk *rsa.PublicKey, msg, signature []byte) error {
	r := sha256.Sum256(msg)
	return rsa.VerifyPSS(pk, crypto.SHA256, r[:], signature, nil)
}

// ResultToShareSecretKey converts a private share at kyber DKG result to github.com/herumi/bls-eth-go-binary/bls private key
func ResultToShareSecretKey(result *drand_dkg.DistKeyShare) (*bls.SecretKey, error) {
	privShare := result.PriShare()
	bytsSk, err := privShare.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

// KyberShareToBLSKey converts a kyber private share to github.com/herumi/bls-eth-go-binary/bls private key
func KyberShareToBLSKey(privShare *share.PriShare) (*bls.SecretKey, error) {
	bytsSk, err := privShare.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

// ResultsToValidatorPK converts a public polynomial at kyber DKG result to github.com/herumi/bls-eth-go-binary/bls public key
func ResultToValidatorPK(result *drand_dkg.DistKeyShare, suite drand_dkg.Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), result.Commitments())
	bytsPK, err := exp.Commit().MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal share")
	}
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(bytsPK); err != nil {
		return nil, err
	}
	return pk, nil
}

// ParseRSAPubkey parses encoded to base64 x509 RSA public key
func ParseRSAPubkey(pk []byte) (*rsa.PublicKey, error) {
	operatorKeyByte, err := base64.StdEncoding.DecodeString(string(pk))
	if err != nil {
		return nil, err
	}
	pemblock, _ := pem.Decode(operatorKeyByte)
	if pemblock == nil {
		return nil, errors.New("decode PEM block")
	}
	pbkey, err := x509.ParsePKIXPublicKey(pemblock.Bytes)
	if err != nil {
		return nil, err
	}
	return pbkey.(*rsa.PublicKey), nil
}

func EncodePublicKey(pk *rsa.PublicKey) ([]byte, error) {
	pkBytes, err := x509.MarshalPKIXPublicKey(pk)
	if err != nil {
		return nil, err
	}
	pemByte := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PUBLIC KEY",
			Bytes: pkBytes,
		},
	)
	if pemByte == nil {
		return nil, fmt.Errorf("failed to encode pub key to pem")
	}

	return []byte(base64.StdEncoding.EncodeToString(pemByte)), nil
}

// VerifyOwnerNonceSignature check that owner + nonce correctly signed
func VerifyOwnerNonceSignature(sig []byte, owner common.Address, pubKey []byte, nonce uint16) error {
	data := fmt.Sprintf("%s:%d", owner.String(), nonce)
	hash := eth_crypto.Keccak256([]byte(data))

	sign := &bls.Sign{}
	if err := sign.Deserialize(sig); err != nil {
		return fmt.Errorf("failed to deserialize signature: %w", err)
	}

	pk := &bls.PublicKey{}
	if err := pk.Deserialize(pubKey); err != nil {
		return fmt.Errorf("failed to deserialize public key: %w", err)
	}

	if res := sign.VerifyByte(pk, hash); !res {
		return errors.New("failed to verify signature")
	}

	return nil
}

// ReadEncryptedPrivateKey return rsa private key from secret key
func ReadEncryptedPrivateKey(keyData []byte, password string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("Password required for encrypted PEM block")
	}

	// Unmarshal the JSON-encoded data
	var data map[string]interface{}
	if err := json.Unmarshal(keyData, &data); err != nil {
		return nil, fmt.Errorf("parse JSON data: %w", err)
	}

	// Decrypt the private key using keystorev4
	decryptedBytes, err := keystorev4.New().Decrypt(data, password)
	if err != nil {
		return nil, fmt.Errorf("decrypt private key: %w", err)
	}

	// Parse the decrypted PEM data
	block, _ := pem.Decode(decryptedBytes)
	if block == nil {
		return nil, errors.New("parse PEM block")
	}

	// Parse the RSA private key
	rsaKey, err := x509.ParsePKCS1PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("parse RSA private key: %w", err)
	}

	return rsaKey, nil
}

// ConvertPemToPrivateKey return rsa private key from secret key
func ConvertPemToPrivateKey(skPem string) (*rsa.PrivateKey, error) {
	block, _ := pem.Decode([]byte(skPem))
	if block == nil {
		return nil, errors.New("decode PEM block")
	}
	b := block.Bytes
	return parsePrivateKey(b)
}

// parsePrivateKey parses an encoded x509 RSA private key
func parsePrivateKey(derBytes []byte) (*rsa.PrivateKey, error) {
	parsedSk, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse private key")
	}
	return parsedSk, nil
}

// RecoverValidatorPublicKey recovers a BLS master public key (validator pub key) from provided partial pub keys
func RecoverValidatorPublicKey(ids []uint64, sharePks []*bls.PublicKey) (*bls.PublicKey, error) {
	if len(ids) != len(sharePks) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	validatorRecoveredPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *sharePks[i])
	}
	if err := validatorRecoveredPK.Recover(pkVec, idVec); err != nil {
		return nil, fmt.Errorf("error recovering validator pub key from shares")
	}
	return &validatorRecoveredPK, nil
}

// RecoverMasterSig recovers a BLS master signature from T-threshold partial signatures
func RecoverMasterSig(ids []uint64, sigDepositShares []*bls.Sign) (*bls.Sign, error) {
	if len(ids) != len(sigDepositShares) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	reconstructedDepositMasterSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		sigVec = append(sigVec, *sigDepositShares[i])
	}
	if err := reconstructedDepositMasterSig.Recover(sigVec, idVec); err != nil {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	return &reconstructedDepositMasterSig, nil
}

// DepositData crates and signs a ETH2 deposit message
func DepositData(masterSig, withdrawalPubKey, publicKey []byte, network e2m_core.Network, amount phase0.Gwei) (*phase0.DepositData, [32]byte, error) {
	if !e2m_deposit.IsSupportedDepositNetwork(network) {
		return nil, [32]byte{}, fmt.Errorf("network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: ETH1WithdrawalCredentialsHash(withdrawalPubKey),
		Amount:                amount,
	}
	copy(depositMessage.PublicKey[:], publicKey)

	objRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}

	// Compute domain
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to calculate domain: %s", err)
	}

	signingData := phase0.SigningData{
		ObjectRoot: objRoot,
	}
	copy(signingData.Domain[:], domain)

	signedDepositData := &phase0.DepositData{
		Amount:                amount,
		WithdrawalCredentials: depositMessage.WithdrawalCredentials,
	}
	copy(signedDepositData.PublicKey[:], publicKey)
	copy(signedDepositData.Signature[:], masterSig)

	depositDataRoot, err := signedDepositData.HashTreeRoot()
	if err != nil {
		return nil, [32]byte{}, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}

	return signedDepositData, depositDataRoot, nil
}

// withdrawalCredentialsHash forms a 32 byte hash of the withdrawal public
// address.
//
// The specification is as follows:
//
//	withdrawal_credentials[:1] == BLS_WITHDRAWAL_PREFIX_BYTE
//	withdrawal_credentials[1:] == hash(withdrawal_pubkey)[1:]
//
// where withdrawal_credentials is of type bytes32.
func BLSWithdrawalCredentialsHash(withdrawalPubKey []byte) []byte {
	h := util.SHA256(withdrawalPubKey)
	return append([]byte{BLSWithdrawalPrefixByte}, h[1:]...)[:32]
}

func ETH1WithdrawalCredentialsHash(withdrawalAddr []byte) []byte {
	withdrawalCredentials := make([]byte, 32)
	copy(withdrawalCredentials[:1], []byte{ETH1WithdrawalPrefixByte})
	// withdrawalCredentials[1:12] == b'\x00' * 11 // this is not needed since cells are zeroed anyway
	copy(withdrawalCredentials[12:], withdrawalAddr)
	return withdrawalCredentials
}

// DepositDataRoot computes a deposit root used for ETH2 deposit message
func DepositDataRoot(withdrawalPubKey []byte, publicKey *bls.PublicKey, network e2m_core.Network, amount phase0.Gwei) ([]byte, error) {
	if !e2m_deposit.IsSupportedDepositNetwork(network) {
		return nil, fmt.Errorf("network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: ETH1WithdrawalCredentialsHash(withdrawalPubKey),
		Amount:                amount,
	}
	copy(depositMessage.PublicKey[:], publicKey.Serialize())

	objRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine the root hash of deposit data: %s", err)
	}

	// Compute domain
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, fmt.Errorf("failed to calculate domain: %s", err)
	}

	signingData := phase0.SigningData{
		ObjectRoot: objRoot,
	}
	copy(signingData.Domain[:], domain)

	root, err := signingData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine the root hash of signing container: %s", err)
	}

	return root[:], nil
}

// VerifyDepositData reconstructs and checks BLS signatures for ETH2 deposit message
func VerifyDepositData(depositData *phase0.DepositData, network e2m_core.Network) (bool, error) {
	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: depositData.WithdrawalCredentials,
		Amount:                depositData.Amount,
	}
	copy(depositMessage.PublicKey[:], depositData.PublicKey[:])

	depositMsgRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return false, err
	}

	sigBytes := make([]byte, len(depositData.Signature))
	copy(sigBytes, depositData.Signature[:])
	sig, err := types.BLSSignatureFromBytes(sigBytes)
	if err != nil {
		return false, err
	}

	container := &phase0.SigningData{
		ObjectRoot: depositMsgRoot,
	}

	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return false, err
	}
	copy(container.Domain[:], domain)
	signingRoot, err := container.HashTreeRoot()
	if err != nil {
		return false, err
	}

	var pubkeyBytes [48]byte
	copy(pubkeyBytes[:], depositData.PublicKey[:])

	pubkey, err := types.BLSPublicKeyFromBytes(pubkeyBytes[:])
	if err != nil {
		return false, err
	}
	return sig.Verify(signingRoot[:], pubkey), nil
}

// SignDepositData creates a BLS signature for ETH2 deposit message
func SignDepositData(validationKey *bls.SecretKey, withdrawalPubKey []byte, validatorPublicKey *bls.PublicKey, network e2m_core.Network, amount phase0.Gwei) (*bls.Sign, []byte, error) {
	if !e2m_deposit.IsSupportedDepositNetwork(network) {
		return nil, nil, errors.Errorf("Network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: ETH1WithdrawalCredentialsHash(withdrawalPubKey),
		Amount:                amount,
	}
	copy(depositMessage.PublicKey[:], validatorPublicKey.Serialize())

	objRoot, err := depositMessage.HashTreeRoot()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to determine the root hash of deposit data")
	}

	// Compute domain
	genesisForkVersion := network.GenesisForkVersion()
	domain, err := types.ComputeDomain(types.DomainDeposit, genesisForkVersion[:], types.ZeroGenesisValidatorsRoot)
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to calculate domain")
	}

	signingData := phase0.SigningData{
		ObjectRoot: objRoot,
	}
	copy(signingData.Domain[:], domain)

	root, err := signingData.HashTreeRoot()
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to determine the root hash of signing container")
	}

	// Sign
	sig := validationKey.SignByte(root[:])
	if err != nil {
		return nil, nil, errors.Wrap(err, "failed to sign the root")
	}
	return sig, root[:], nil
}

// VerifyPartialSigs verifies provided partial BLS signatures
func VerifyPartialSigs(sigShares []*bls.Sign, sharePks []*bls.PublicKey, data []byte) error {
	if len(sigShares) != len(sharePks) {
		return fmt.Errorf("inconsistent slice lengths")
	}
	res := make([]bool, len(sigShares))
	for i := 0; i < len(sigShares); i++ {
		if sigShares[i].VerifyByte(sharePks[i], data) {
			res[i] = true
		}
	}

	var errStr = ""

	for index, r := range res {
		if !r {
			errStr += fmt.Sprintf(" id %d sig %x root %x, errStr", index, sigShares[index].Serialize(), data)
			continue
		}
	}
	if errStr != "" {
		return fmt.Errorf("error verifying partial deposit signature: %v", errStr)
	}
	return nil
}

// EncryptedPrivateKey reads  an encoded RSA priv key from path encrypted with password
func EncryptedPrivateKey(path, pass string) (*rsa.PrivateKey, error) {
	data, err := os.ReadFile(filepath.Clean(path))
	if err != nil {
		return nil, fmt.Errorf("failed to read file: %w", err)
	}

	privateKey, err := ReadEncryptedPrivateKey(data, pass)
	if err != nil {
		return nil, err
	}

	return privateKey, nil
}

// NewID generates a random ID from 2 random concat UUIDs
func NewID() [24]byte {
	var id [24]byte
	b := uuid.New()
	copy(id[:12], b[:])
	b = uuid.New()
	copy(id[12:], b[:])
	return id
}

// GenerateSecurePassword randomly generates a password consisting of digits + english letters
func GenerateSecurePassword() (string, error) {
	const alpha = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ"
	var pass []rune
	p := make([]byte, 64)
	if _, err := rand.Reader.Read(p); err != nil {
		return "", err
	}
	hash := sha512.Sum512(p)
	for _, r := range string(hash[:]) {
		if unicode.IsDigit(r) || strings.Contains(alpha, strings.ToLower(string(r))) {
			pass = append(pass, r)
		}
	}
	return string(pass), nil
}

// ReconstructSignatures receives a map of user indexes and serialized bls.Sign.
// It then reconstructs the original threshold signature using lagrange interpolation
func ReconstructSignatures(ids []uint64, signatures [][]byte) (*bls.Sign, error) {
	if len(ids) != len(signatures) {
		return nil, fmt.Errorf("inconsistent IDs len")
	}
	reconstructedSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for i, index := range ids {
		blsID := bls.ID{}
		err := blsID.SetDecString(fmt.Sprintf("%d", index))
		if err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		blsSig := bls.Sign{}

		err = blsSig.Deserialize(signatures[i])
		if err != nil {
			return nil, err
		}
		sigVec = append(sigVec, blsSig)
	}
	err := reconstructedSig.Recover(sigVec, idVec)
	return &reconstructedSig, err
}

// VerifyReconstructedSignature checks a reconstructed msg master signature against validator public key
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

func ReadEncryptedRSAKey(privKeyPath, privKeyPassPath string) (*rsa.PrivateKey, error) {
	keyStorePassword, err := os.ReadFile(filepath.Clean(privKeyPassPath))
	if err != nil {
		return nil, fmt.Errorf("😥 Cant read operator`s key file: %s", err)
	}
	return EncryptedPrivateKey(privKeyPath, string(keyStorePassword))
}

func EncryptPrivateKey(priv []byte, keyStorePassword string) ([]byte, error) {
	encryptedData, err := keystorev4.New().Encrypt(priv, keyStorePassword)
	if err != nil {
		return nil, fmt.Errorf("😥 Failed to encrypt private key: %s", err)
	}
	return json.Marshal(encryptedData)
}

func GetPubCommitsFromSharesData(oldOps []*wire.Operator, keyShares []byte, t int) ([]kyber.Point, error) {
	suite := kyber_bls12381.NewBLS12381Suite()
	signatureOffset := phase0.SignatureLength
	pubKeysOffset := phase0.PublicKeyLength*len(oldOps) + signatureOffset
	sharesExpectedLength := EncryptedKeyLength*len(oldOps) + pubKeysOffset
	if len(keyShares) != sharesExpectedLength {
		return nil, fmt.Errorf("GetPubCommitsFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	pubKeys := utils.SplitBytes(keyShares[signatureOffset:pubKeysOffset], phase0.PublicKeyLength)
	// try to recover commits
	var kyberPubShares []*share.PubShare
	for i, pubk := range pubKeys {
		blsPub := &bls.PublicKey{}
		err := blsPub.Deserialize(pubk)
		if err != nil {
			return nil, err
		}
		v := suite.G1().Point()
		err = v.UnmarshalBinary(blsPub.Serialize())
		if err != nil {
			return nil, err
		}
		kyberPubhare := &share.PubShare{
			I: int(oldOps[i].ID - 1),
			V: v,
		}
		kyberPubShares = append(kyberPubShares, kyberPubhare)
	}
	pubPoly, err := share.RecoverPubPoly(suite.G1(), kyberPubShares, t, len(oldOps))
	if err != nil {
		return nil, err
	}
	_, commits := pubPoly.Info()
	return commits, nil
}

func GetSecretShareFromSharesData(keyshares []byte, oldOperators []*wire.Operator, opPrivateKey *rsa.PrivateKey, operatorID uint64) (*share.PriShare, error) {
	suite := kyber_bls12381.NewBLS12381Suite()
	secret, _, err := checkKeySharesSlice(keyshares, oldOperators, operatorID, opPrivateKey)
	if err != nil {
		return nil, err
	}
	var kyberPrivShare *share.PriShare
	// // Check operator signature
	// initiatorPubKey, err := ParseRSAPubkey(initiatorPublicKey)
	// if err != nil {
	// 	return nil, err
	// }
	// encInitPub, err := EncodePublicKey(initiatorPubKey)
	// if err != nil {
	// 	return nil, err
	// }
	// sigs := utils.SplitBytes(ceremonySigs, SignatureLength)
	serialized := secret.Serialize()
	// dataToVerify := make([]byte, len(serialized)+len(encInitPub))
	// copy(dataToVerify[:len(serialized)], serialized)
	// copy(dataToVerify[len(serialized):], encInitPub)
	// err = VerifyRSA(&opPrivateKey.PublicKey, dataToVerify, sigs[position])
	// if err != nil {
	// 	return nil, fmt.Errorf("cant verify initiator public key")
	// }
	v := suite.G1().Scalar().SetBytes(serialized)
	kyberPrivShare = &share.PriShare{
		I: int(operatorID - 1),
		V: v,
	}
	return kyberPrivShare, nil
}

func checkKeySharesSlice(keyShares []byte, oldOperators []*wire.Operator, operatorID uint64, opPrivateKey *rsa.PrivateKey) (*bls.SecretKey, int, error) {
	pubKeyOffset := phase0.PublicKeyLength * len(oldOperators)
	pubKeysSigOffset := pubKeyOffset + phase0.SignatureLength
	sharesExpectedLength := EncryptedKeyLength*len(oldOperators) + pubKeysSigOffset
	if len(keyShares) != sharesExpectedLength {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: shares data len is not correct, expected %d, actual %d", sharesExpectedLength, len(keyShares))
	}
	position := -1
	for i, op := range oldOperators {
		if operatorID == op.ID {
			position = i
			break
		}
	}
	// check
	if position == -1 {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: operator not found among old operators: %d", operatorID)
	}
	encryptedKeys := utils.SplitBytes(keyShares[pubKeysSigOffset:], len(keyShares[pubKeysSigOffset:])/len(oldOperators))
	// try to decrypt private share
	prShare, err := rsaencryption.DecodeKey(opPrivateKey, encryptedKeys[position])
	if err != nil {
		return nil, 0, err
	}
	secret := &bls.SecretKey{}
	err = secret.SetHexString(string(prShare))
	if err != nil {
		return nil, 0, err
	}
	// find share pub key
	pubKeys := utils.SplitBytes(keyShares[phase0.SignatureLength:pubKeysSigOffset], phase0.PublicKeyLength)
	if len(pubKeys) != len(oldOperators) {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: amount of public keys at keyshares slice is wrong: %d", len(pubKeys))
	}
	publicKey := &bls.PublicKey{}
	err = publicKey.Deserialize(pubKeys[position])
	if err != nil {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: cant deserialize public key at keyshares slice: %d", len(pubKeys))
	}
	if !bytes.Equal(publicKey.Serialize(), secret.GetPublicKey().Serialize()) {
		return nil, 0, fmt.Errorf("GetSecretShareFromSharesData: public key at position %d not equal to operator`s share public key", position)
	}
	return secret, position, nil
}
