package wire

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestEncodeDecodeInitiatorErrorCode_RoundTrip(t *testing.T) {
	encoded := InitiatorErrorCodeCeremonyFailed.Encode()
	decoded := ParseInitiatorErrorMessage(encoded)
	require.Equal(t, string(InitiatorErrorCodeCeremonyFailed), decoded)
}

func TestParseInitiatorErrorMessage_FallbackRawBytes(t *testing.T) {
	decoded := ParseInitiatorErrorMessage([]byte("CEREMONY_FAILED"))
	require.Equal(t, "CEREMONY_FAILED", decoded)
}
