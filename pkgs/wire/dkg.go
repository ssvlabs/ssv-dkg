package wire

import (
	"fmt"
	"time"

	"github.com/drand/kyber/share/dkg"
	"go.uber.org/zap"
)

// NonceLength is the length of the nonce
const NonceLength = 32

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
func NewDKGProtocol(dkgConfig *dkg.Config, b dkg.Board, logger *zap.Logger) (*dkg.Protocol, error) {
	dkgLogger := New(logger)
	dkgConfig.Log = dkgLogger
	// Phaser must signal on its channel when the protocol should move to a next
	// phase. Phase must be sequential: DealPhase (start), ResponsePhase,
	// JustifPhase and then FinishPhase.
	phaser := dkg.NewTimePhaser(time.Second * 5)
	ret, err := dkg.NewProtocol(
		dkgConfig,
		b,
		phaser,
		false,
	)
	if err != nil {
		return nil, err
	}
	go phaser.Start()
	return ret, nil
}
