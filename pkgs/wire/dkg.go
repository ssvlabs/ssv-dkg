package wire

import (
	"crypto/sha256"
	"fmt"
	"time"

	"github.com/drand/kyber"
	"github.com/drand/kyber/pairing"
	"github.com/drand/kyber/share/dkg"
	drand_bls "github.com/drand/kyber/sign/bls"
	"go.uber.org/zap"
)

// NonceLength is the length of the nonce
const NonceLength = 32

// Config structure to configure a DKG protocol instance
type Config struct {
	Identifier   []byte        // DKG instance ID 24 bytes
	Secret       kyber.Scalar  // a secret key crated at Instance initiation
	OldNodes     []dkg.Node    // DKG operators participating at the ceremony
	NewNodes     []dkg.Node    // DKG operators participating at the ceremony
	Suite        pairing.Suite // parameters on the fields being used
	T            int           // threshold - minimum number of participants needed to restore a master private key
	NewT         int           // threshold - minimum number of participants needed to restore a master private key
	Board        dkg.Board     // structure to process DKG messages from other participants
	Share        *dkg.DistKeyShare
	PublicCoeffs []kyber.Point
	Logger       *zap.Logger
}

// LogWrapper is needed because drand/kyber uses dkg.Logger which differs from zap in some methods
type LogWrapper struct {
	Logger *zap.Logger
}

func New(logger *zap.Logger) *LogWrapper {
	return &LogWrapper{Logger: logger}
}
func (l *LogWrapper) Info(vals ...interface{}) {
	l.Logger.Info(fmt.Sprint(vals...))
}

func (l *LogWrapper) Error(vals ...interface{}) {
	l.Logger.Error(fmt.Sprint(vals...))
}

// NewDKGProtocol initializes and starts phases of the DKG protocol
func NewDKGProtocol(config *Config) (*dkg.Protocol, error) {
	dkgLogger := New(config.Logger)
	dkgConfig := &dkg.Config{
		Longterm:  config.Secret,
		Nonce:     GetNonce(config.Identifier),
		Suite:     config.Suite.G1().(dkg.Suite),
		NewNodes:  config.NewNodes,
		OldNodes:  config.NewNodes, // in new dkg we consider the old nodes the new nodes (taken from kyber)
		Threshold: config.T,
		Auth:      drand_bls.NewSchemeOnG2(config.Suite),
		Log:       dkgLogger,
	}
	// Phaser must signal on its channel when the protocol should move to a next
	// phase. Phase must be sequential: DealPhase (start), ResponsePhase,
	// JustifPhase and then FinishPhase.
	phaser := dkg.NewTimePhaser(time.Second * 5)

	ret, err := dkg.NewProtocol(
		dkgConfig,
		config.Board,
		phaser,
		false,
	)
	if err != nil {
		return nil, err
	}

	go phaser.Start()

	return ret, nil
}

func NewReshareProtocolOldNodes(config *Config) (*dkg.Protocol, error) {
	dkgLogger := New(config.Logger)
	dkgConfig := &dkg.Config{
		Longterm:     config.Secret,
		Nonce:        GetNonce(config.Identifier),
		Suite:        config.Suite.G1().(dkg.Suite),
		NewNodes:     config.NewNodes,
		OldNodes:     config.OldNodes, // in new dkg we consider the old nodes the new nodes (taken from kyber)
		Threshold:    config.NewT,
		OldThreshold: config.T,
		Auth:         drand_bls.NewSchemeOnG2(config.Suite),
		Log:          dkgLogger,
		Share:        config.Share,
	}

	phaser := dkg.NewTimePhaser(time.Second * 5)

	ret, err := dkg.NewProtocol(
		dkgConfig,
		config.Board,
		phaser,
		false,
	)
	if err != nil {
		return nil, err
	}

	go phaser.Start()

	return ret, nil
}
func NewReshareProtocolNewNodes(config *Config) (*dkg.Protocol, error) {
	dkgLogger := New(config.Logger)
	dkgConfig := &dkg.Config{
		Longterm:     config.Secret,
		Nonce:        GetNonce(config.Identifier),
		Suite:        config.Suite.G1().(dkg.Suite),
		NewNodes:     config.NewNodes,
		OldNodes:     config.OldNodes, // in new dkg we consider the old nodes the new nodes (taken from kyber)
		Threshold:    config.NewT,
		OldThreshold: config.T,
		Auth:         drand_bls.NewSchemeOnG2(config.Suite),
		Log:          dkgLogger,
		PublicCoeffs: config.PublicCoeffs,
	}

	phaser := dkg.NewTimePhaser(time.Second * 5)

	ret, err := dkg.NewProtocol(
		dkgConfig,
		config.Board,
		phaser,
		false,
	)
	if err != nil {
		return nil, err
	}

	go phaser.Start()
	return ret, nil
}

// GetNonce returns a suitable nonce to feed in the DKG config.
func GetNonce(input []byte) []byte {
	ret := sha256.Sum256(input)
	return ret[:]
}
