package wire

import "encoding/json"

// InitiatorErrorCode is a stable error code intended to be sent over the wire to
// the ceremony initiator. It must not include internal failure details.
type InitiatorErrorCode string

const (
	// InitiatorErrorCodeCeremonyFailed is the generic failure code for any ceremony failure.
	InitiatorErrorCodeCeremonyFailed InitiatorErrorCode = "CEREMONY_FAILED"
)

// EncodeInitiatorErrorCode JSON-marshals the error code for transport.
func EncodeInitiatorErrorCode(code InitiatorErrorCode) []byte {
	// Marshaling a string cannot fail; ignore the error for simplicity.
	encoded, _ := json.Marshal(code)
	return encoded
}

// DecodeInitiatorErrorMessage attempts to decode a JSON-marshaled string. If it
// fails, it falls back to returning the raw payload as a string (backwards
// compatible with any legacy non-JSON payloads).
func DecodeInitiatorErrorMessage(data []byte) string {
	var decoded string
	if err := json.Unmarshal(data, &decoded); err == nil {
		return decoded
	}
	return string(data)
}
