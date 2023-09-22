package crypto

import (
	"crypto"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/uuid"
	"strings"

	"github.com/attestantio/go-eth2-client/spec/phase0"
	eth2_key_manager_core "github.com/bloxapp/eth2-key-manager/core"
	"github.com/drand/kyber/share"
	"github.com/drand/kyber/share/dkg"
	"github.com/ethereum/go-ethereum/common"
	eth_crypto "github.com/ethereum/go-ethereum/crypto"
	"github.com/herumi/bls-eth-go-binary/bls"
	"github.com/pkg/errors"
	types "github.com/wealdtech/go-eth2-types/v2"
	util "github.com/wealdtech/go-eth2-util"
	keystorev4 "github.com/wealdtech/go-eth2-wallet-encryptor-keystorev4"
)

const (
	// BLSWithdrawalPrefixByte is the BLS withdrawal prefix
	BLSWithdrawalPrefixByte = byte(0)
)

func init() {
	_ = bls.Init(bls.BLS12_381)
	_ = bls.SetETHmode(bls.EthModeDraft07)
}

func GenerateKeys() (*rsa.PrivateKey, *rsa.PublicKey, error) {
	pv, err := rsa.GenerateKey(rand.Reader, 1024)
	if err != nil {
		return nil, nil, err
	}

	return pv, &pv.PublicKey, nil

}

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

func VerifyRSA(pk *rsa.PublicKey, msg, signature []byte) error {
	r := sha256.Sum256(msg)
	return rsa.VerifyPSS(pk, crypto.SHA256, r[:], signature, nil)
}

func ResultToShareSecretKey(result *dkg.Result) (*bls.SecretKey, error) {
	share := result.Key.PriShare()
	bytsSk, err := share.V.MarshalBinary()
	if err != nil {
		return nil, err
	}
	sk := &bls.SecretKey{}
	if err := sk.Deserialize(bytsSk); err != nil {
		return nil, err
	}
	return sk, nil
}

func ResultsToValidatorPK(results []*dkg.Result, suite dkg.Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), results[0].Key.Commitments())
	bytsPK, err := exp.Eval(0).V.MarshalBinary()
	if err != nil {
		return nil, errors.Wrap(err, "could not marshal share")
	}
	pk := &bls.PublicKey{}
	if err := pk.Deserialize(bytsPK); err != nil {
		return nil, err
	}
	return pk, nil
}

func ResultToValidatorPK(result *dkg.Result, suite dkg.Suite) (*bls.PublicKey, error) {
	exp := share.NewPubPoly(suite, suite.Point().Base(), result.Key.Commitments())
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

func ParseRSAPubkey(pk []byte) (*rsa.PublicKey, error) {
	operatorKeyByte, err := base64.StdEncoding.DecodeString(string(pk))
	if err != nil {
		return nil, err
	}
	pemblock, _ := pem.Decode(operatorKeyByte)
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

	return []byte(base64.StdEncoding.EncodeToString(pemByte)), nil
}

func VerifyOwnerNoceSignature(sig []byte, owner common.Address, pubKey []byte, nonce uint16) error {
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

// ConvertEncryptedPemToPrivateKey return rsa private key from secret key
func ConvertEncryptedPemToPrivateKey(pemData []byte, password string) (*rsa.PrivateKey, error) {
	if strings.TrimSpace(password) == "" {
		return nil, errors.New("Password required for encrypted PEM block")
	}

	// Unmarshal the JSON-encoded data
	var data map[string]interface{}
	if err := json.Unmarshal(pemData, &data); err != nil {
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

// ExtractPrivateKey gets private key and returns base64 encoded private key
func ExtractPrivateKey(sk *rsa.PrivateKey) string {
	pemByte := pem.EncodeToMemory(
		&pem.Block{
			Type:  "RSA PRIVATE KEY",
			Bytes: x509.MarshalPKCS1PrivateKey(sk),
		},
	)
	return base64.StdEncoding.EncodeToString(pemByte)
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

func parsePrivateKey(derBytes []byte) (*rsa.PrivateKey, error) {
	parsedSk, err := x509.ParsePKCS1PrivateKey(derBytes)
	if err != nil {
		return nil, errors.Wrap(err, "Failed to parse private key")
	}
	return parsedSk, nil
}

func RecoverValidatorPublicKey(sharePks map[uint64]*bls.PublicKey) (*bls.PublicKey, error) {
	validatorRecoveredPK := bls.PublicKey{}
	idVec := make([]bls.ID, 0)
	pkVec := make([]bls.PublicKey, 0)
	for index, pk := range sharePks {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		pkVec = append(pkVec, *pk)
	}
	if err := validatorRecoveredPK.Recover(pkVec, idVec); err != nil {
		return nil, fmt.Errorf("error recovering validator pub key from shares")
	}
	return &validatorRecoveredPK, nil
}
func RecoverMasterSig(sigDepositShares map[uint64]*bls.Sign) (*bls.Sign, error) {
	reconstructedDepositMasterSig := bls.Sign{}
	idVec := make([]bls.ID, 0)
	sigVec := make([]bls.Sign, 0)
	for index, sig := range sigDepositShares {
		blsID := bls.ID{}
		if err := blsID.SetDecString(fmt.Sprintf("%d", index)); err != nil {
			return nil, err
		}
		idVec = append(idVec, blsID)
		sigVec = append(sigVec, *sig)
	}
	if err := reconstructedDepositMasterSig.Recover(sigVec, idVec); err != nil {
		return nil, fmt.Errorf("deposit root signature recovered from shares is invalid")
	}
	return &reconstructedDepositMasterSig, nil
}

func DepositData(masterSig, withdrawalPubKey, publicKey []byte, network eth2_key_manager_core.Network, amount phase0.Gwei) (*phase0.DepositData, [32]byte, error) {
	if !IsSupportedDepositNetwork(network) {
		return nil, [32]byte{}, fmt.Errorf("network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: WithdrawalCredentialsHash(withdrawalPubKey),
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
	copy(signingData.Domain[:], domain[:])

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
func WithdrawalCredentialsHash(withdrawalPubKey []byte) []byte {
	h := util.SHA256(withdrawalPubKey)
	return append([]byte{BLSWithdrawalPrefixByte}, h[1:]...)[:32]
}

// IsSupportedDepositNetwork returns true if the given network is supported
var IsSupportedDepositNetwork = func(network eth2_key_manager_core.Network) bool {
	return network == eth2_key_manager_core.PyrmontNetwork || network == eth2_key_manager_core.PraterNetwork || network == eth2_key_manager_core.MainNetwork
}

func DepositDataRoot(withdrawalPubKey []byte, publicKey *bls.PublicKey, network eth2_key_manager_core.Network, amount phase0.Gwei) ([]byte, error) {
	if !IsSupportedDepositNetwork(network) {
		return nil, fmt.Errorf("network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: WithdrawalCredentialsHash(withdrawalPubKey),
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
	copy(signingData.Domain[:], domain[:])

	root, err := signingData.HashTreeRoot()
	if err != nil {
		return nil, fmt.Errorf("failed to determine the root hash of signing container: %s", err)
	}

	return root[:], nil
}

func VerifyDepositData(depositData *phase0.DepositData, network eth2_key_manager_core.Network) (bool, error) {
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
	copy(container.Domain[:], domain[:])
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

func SignDepositData(validationKey *bls.SecretKey, withdrawalPubKey []byte, validatorPublicKey *bls.PublicKey, network eth2_key_manager_core.Network, amount phase0.Gwei) (*bls.Sign, []byte, error) {
	if !IsSupportedDepositNetwork(network) {
		return nil, nil, errors.Errorf("Network %s is not supported", network)
	}

	depositMessage := &phase0.DepositMessage{
		WithdrawalCredentials: WithdrawalCredentialsHash(withdrawalPubKey),
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
	copy(signingData.Domain[:], domain[:])

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

func VerifyPartialSigs(sigShares map[uint64]*bls.Sign, sharePks map[uint64]*bls.PublicKey, data []byte) error {
	for index, pub := range sharePks {
		if !sigShares[index].VerifyByte(pub, data) {
			return fmt.Errorf("error verifying partial deposit signature: sig %x, root %x", sigShares[index].Serialize(), data)
		}
	}
	return nil
}

func NewID() [24]byte {
	var id [24]byte
	b := uuid.New()
	b2 := uuid.New() // random ID for each new DKG initiation
	copy(id[:16], b[:])
	copy(id[16:], b2[:8])
	//copy(id[8:], b[:])
	return id
}
