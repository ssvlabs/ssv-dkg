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

type Config struct {
	Identifier []byte
	// Secret session secret key
	Secret       kyber.Scalar
	OldNodes     []dkg.Node
	NewNodes     []dkg.Node
	Suite        pairing.Suite
	T            int
	NewT         int
	Board        dkg.Board
	Share        *dkg.DistKeyShare
	PublicCoeffs []kyber.Point
	Logger       *zap.Logger
}

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

func NewDKGProtocol(config *Config) (*dkg.Protocol, error) {
	dkgLogger := New(config.Logger)
	dkgConfig := &dkg.Config{
		Longterm:     config.Secret,
		Nonce:        GetNonce(config.Identifier),
		Suite:        config.Suite.G1().(dkg.Suite),
		NewNodes:     config.NewNodes,
		OldNodes:     config.OldNodes, // in new dkg we consider the old nodes the new nodes (taken from kyber)
		Threshold:    config.T,
		OldThreshold: config.NewT,
		Auth:         drand_bls.NewSchemeOnG2(config.Suite),
		Share:        config.Share,
		PublicCoeffs: config.PublicCoeffs,
		Log:          dkgLogger,
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
