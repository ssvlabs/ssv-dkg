package wire

import "testing"

func TestEncodeDecodeInitiatorErrorCode_RoundTrip(t *testing.T) {
	encoded := EncodeInitiatorErrorCode(InitiatorErrorCodeCeremonyFailed)
	decoded := DecodeInitiatorErrorMessage(encoded)
	if decoded != string(InitiatorErrorCodeCeremonyFailed) {
		t.Fatalf("expected %q, got %q", InitiatorErrorCodeCeremonyFailed, decoded)
	}
}

func TestDecodeInitiatorErrorMessage_FallbackRawBytes(t *testing.T) {
	decoded := DecodeInitiatorErrorMessage([]byte("CEREMONY_FAILED"))
	if decoded != "CEREMONY_FAILED" {
		t.Fatalf("expected %q, got %q", "CEREMONY_FAILED", decoded)
	}
}
