package utils

import (
	"testing"

	"github.com/stretchr/testify/require"
)

func TestHexToAddress(t *testing.T) {
	var valid1 = "0x81592c3DE184A3E2c0DCB5a261BC107Bfa91f494"
	var valid2 = "81592c3DE184A3E2c0DCB5a261BC107Bfa91f494"
	var inValid1 = "0x81592c3de184a3e2c0dcb5a261bc107bfa91f49"
	var inValid2 = "81592c3de184a3e2c0dcb5a261bc107bfa91f49"
	var inValid3 = "0x81592c3de184a3e2c0dcb5a261bc107bfa91f491010101"
	var inValid4 = "not_valid"
	t.Run("test valid", func(t *testing.T) {
		address, err := HexToAddress(valid1)
		require.NoError(t, err)
		require.Equal(t, valid1, address.Hex())
	})
	t.Run("test valid no 0x", func(t *testing.T) {
		address, err := HexToAddress(valid2)
		require.NoError(t, err)
		require.Equal(t, valid1, address.Hex())
	})
	t.Run("test invalid len < 20", func(t *testing.T) {
		_, err := HexToAddress(inValid1)
		require.ErrorContains(t, err, "encoding/hex: odd length hex string")
	})
	t.Run("test invalid len + no 0x", func(t *testing.T) {
		_, err := HexToAddress(inValid2)
		require.ErrorContains(t, err, "encoding/hex: odd length hex string")
	})
	t.Run("test invalid len > 20", func(t *testing.T) {
		_, err := HexToAddress(inValid3)
		require.ErrorContains(t, err, "not valid ETH address with len")
	})
	t.Run("test invalid len > 20", func(t *testing.T) {
		_, err := HexToAddress(inValid3)
		require.ErrorContains(t, err, "not valid ETH address with len")
	})
	t.Run("test invalid hex", func(t *testing.T) {
		_, err := HexToAddress(inValid4)
		require.ErrorContains(t, err, "encoding/hex: invalid byte")
	})
}
