package utils

import (
	"testing"

	"github.com/stretchr/testify/require"

	spec "github.com/ssvlabs/dkg-spec"
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

func TestJoinSets(t *testing.T) {
	t.Run("test join sets: wrong op len", func(t *testing.T) {
		oldOperators := []*spec.Operator{}
		newOperators := []*spec.Operator{}
		_, err := JoinSets(oldOperators, newOperators)
		require.ErrorContains(t, err, "wrong old ops len: amount of operators should be 4,7,10,13: got 0")
		oldOperators = []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 9, PubKey: []byte{9}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
			&spec.Operator{ID: 14, PubKey: []byte{14}},
		}
		_, err = JoinSets(oldOperators, newOperators)
		require.ErrorContains(t, err, "wrong old ops len: amount of operators should be 4,7,10,13: got 14")
	})
	t.Run("test join sets: [1,2,3,4] and [1,2,3,4] will return [1,2,3,4]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		joinedSets, err := JoinSets(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test join sets: [1,2,3,4] and [1,2,5,6,7] will return [1,2,3,4,5,7]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
		}
		joinedSets, err := JoinSets(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test join sets: [1,2,3,4] and [1,2,3,4] will return [1,2,3,4]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		joinedSets, err := JoinSets(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test join sets:  [1,2,3,4] and [5,6,7,8,11,12,13] will return [1,2,3,4,5,6,7,8,11,12,13]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		joinedSets, err := JoinSets(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test join sets: [1,2,3,4] and [10,11,12,13] will return [1,2,3,4,10,11,12,13]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 10, PubKey: []byte{10}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		joinedSets, err := JoinSets(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test join sets:  [11,22,303,4004,133,122,133,88] and [10001,11,122,133] will return [11,22,88,122,133,303,4004,10001]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 11, PubKey: []byte{}},
			&spec.Operator{ID: 22, PubKey: []byte{}},
			&spec.Operator{ID: 303, PubKey: []byte{}},
			&spec.Operator{ID: 4004, PubKey: []byte{}},
			&spec.Operator{ID: 122, PubKey: []byte{}},
			&spec.Operator{ID: 133, PubKey: []byte{}},
			&spec.Operator{ID: 88, PubKey: []byte{}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 10001, PubKey: []byte{}},
			&spec.Operator{ID: 11, PubKey: []byte{}},
			&spec.Operator{ID: 122, PubKey: []byte{}},
			&spec.Operator{ID: 133, PubKey: []byte{}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 11, PubKey: []byte{}},
			&spec.Operator{ID: 22, PubKey: []byte{}},
			&spec.Operator{ID: 88, PubKey: []byte{}},
			&spec.Operator{ID: 122, PubKey: []byte{}},
			&spec.Operator{ID: 133, PubKey: []byte{}},
			&spec.Operator{ID: 303, PubKey: []byte{}},
			&spec.Operator{ID: 4004, PubKey: []byte{}},
			&spec.Operator{ID: 10001, PubKey: []byte{}},
		}
		joinedSets, err := JoinSets(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
}

func TestGetCommonOldOperators(t *testing.T) {
	t.Run("test common old ops: old set [1,2,3,4]; new set [3,4,5,6,7]; returns [3,4,5]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		joinedSets, err := GetCommonOldOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test common old ops: old set [1,2,3,4]; new set [1,2,3,4]; returns [1,2,3,4]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		joinedSets, err := GetCommonOldOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test common old ops: old set [1,4,7,10]; new set [4,5,6,7,8,9,10,11,12,13]; returns [4,7,10]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 9, PubKey: []byte{9}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
		}
		joinedSets, err := GetCommonOldOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test common old ops: old set [4,5,6,7,8,9,10]; new set [1,2,3,4,11,12,13]; returns [4]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 9, PubKey: []byte{9}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		joinedSets, err := GetCommonOldOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
}

func TestGetDisjointNewOperators(t *testing.T) {
	t.Run("test new ops disjoint from old set: old set [1,2,3,4]; new set [3,4,5,6,7,8,9]; returns [5,6,7,8,9]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 9, PubKey: []byte{9}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 9, PubKey: []byte{9}},
		}
		joinedSets, err := GetDisjointNewOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test new ops disjoint from old set: old set [1,2,3,4]; new set [1,2,3,4]; returns []", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		var expJoinedSets []*spec.Operator
		joinedSets, err := GetDisjointNewOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test new ops disjoint from old set: old set [1,2,3,4,5,6,7,8,9,10,11,12,13]; new set [1,4,7,10]; returns []", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 8, PubKey: []byte{8}},
			&spec.Operator{ID: 9, PubKey: []byte{9}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
			&spec.Operator{ID: 11, PubKey: []byte{11}},
			&spec.Operator{ID: 12, PubKey: []byte{12}},
			&spec.Operator{ID: 13, PubKey: []byte{13}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 7, PubKey: []byte{7}},
			&spec.Operator{ID: 10, PubKey: []byte{10}},
		}
		var expJoinedSets []*spec.Operator
		joinedSets, err := GetDisjointNewOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
	t.Run("test new ops disjoint from old set: old set [1,2,3,4]; new set [3,4,5,6]; returns [5,6]", func(t *testing.T) {
		oldOperators := []*spec.Operator{
			&spec.Operator{ID: 1, PubKey: []byte{1}},
			&spec.Operator{ID: 2, PubKey: []byte{2}},
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
		}
		newOperators := []*spec.Operator{
			&spec.Operator{ID: 3, PubKey: []byte{3}},
			&spec.Operator{ID: 4, PubKey: []byte{4}},
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
		}
		expJoinedSets := []*spec.Operator{
			&spec.Operator{ID: 5, PubKey: []byte{5}},
			&spec.Operator{ID: 6, PubKey: []byte{6}},
		}
		joinedSets, err := GetDisjointNewOperators(oldOperators, newOperators)
		require.NoError(t, err)
		require.Equal(t, expJoinedSets, joinedSets)
	})
}
