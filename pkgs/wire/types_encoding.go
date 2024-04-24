// Code generated by fastssz. DO NOT EDIT.
// Hash: 89e1eba5b6b2d18dd7f88a8b96e805a0dc01d19d027273d14fe7dc15fd69a206
// Version: 0.1.3
package wire

import (
	ssz "github.com/ferranbt/fastssz"
	spec "github.com/ssvlabs/dkg-spec"
)

// MarshalSSZ ssz marshals the MultipleSignedTransports object
func (m *MultipleSignedTransports) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(m)
}

// MarshalSSZTo ssz marshals the MultipleSignedTransports object to a target array
func (m *MultipleSignedTransports) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(32)

	// Field (0) 'Identifier'
	dst = append(dst, m.Identifier[:]...)

	// Offset (1) 'Messages'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(m.Messages); ii++ {
		offset += 4
		offset += m.Messages[ii].SizeSSZ()
	}

	// Offset (2) 'Signature'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(m.Signature)

	// Field (1) 'Messages'
	if size := len(m.Messages); size > 13 {
		err = ssz.ErrListTooBigFn("MultipleSignedTransports.Messages", size, 13)
		return
	}
	{
		offset = 4 * len(m.Messages)
		for ii := 0; ii < len(m.Messages); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += m.Messages[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(m.Messages); ii++ {
		if dst, err = m.Messages[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (2) 'Signature'
	if size := len(m.Signature); size > 2048 {
		err = ssz.ErrBytesLengthFn("MultipleSignedTransports.Signature", size, 2048)
		return
	}
	dst = append(dst, m.Signature...)

	return
}

// UnmarshalSSZ ssz unmarshals the MultipleSignedTransports object
func (m *MultipleSignedTransports) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 32 {
		return ssz.ErrSize
	}

	tail := buf
	var o1, o2 uint64

	// Field (0) 'Identifier'
	copy(m.Identifier[:], buf[0:24])

	// Offset (1) 'Messages'
	if o1 = ssz.ReadOffset(buf[24:28]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 32 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (2) 'Signature'
	if o2 = ssz.ReadOffset(buf[28:32]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (1) 'Messages'
	{
		buf = tail[o1:o2]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		m.Messages = make([]*SignedTransport, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if m.Messages[indx] == nil {
				m.Messages[indx] = new(SignedTransport)
			}
			if err = m.Messages[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (2) 'Signature'
	{
		buf = tail[o2:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(m.Signature) == 0 {
			m.Signature = make([]byte, 0, len(buf))
		}
		m.Signature = append(m.Signature, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the MultipleSignedTransports object
func (m *MultipleSignedTransports) SizeSSZ() (size int) {
	size = 32

	// Field (1) 'Messages'
	for ii := 0; ii < len(m.Messages); ii++ {
		size += 4
		size += m.Messages[ii].SizeSSZ()
	}

	// Field (2) 'Signature'
	size += len(m.Signature)

	return
}

// HashTreeRoot ssz hashes the MultipleSignedTransports object
func (m *MultipleSignedTransports) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(m)
}

// HashTreeRootWith ssz hashes the MultipleSignedTransports object with a hasher
func (m *MultipleSignedTransports) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Identifier'
	hh.PutBytes(m.Identifier[:])

	// Field (1) 'Messages'
	{
		subIndx := hh.Index()
		num := uint64(len(m.Messages))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range m.Messages {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (2) 'Signature'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(m.Signature))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(m.Signature)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the MultipleSignedTransports object
func (m *MultipleSignedTransports) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(m)
}

// MarshalSSZ ssz marshals the ErrSSZ object
func (e *ErrSSZ) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(e)
}

// MarshalSSZTo ssz marshals the ErrSSZ object to a target array
func (e *ErrSSZ) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(4)

	// Offset (0) 'Error'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(e.Error)

	// Field (0) 'Error'
	if size := len(e.Error); size > 512 {
		err = ssz.ErrBytesLengthFn("ErrSSZ.Error", size, 512)
		return
	}
	dst = append(dst, e.Error...)

	return
}

// UnmarshalSSZ ssz unmarshals the ErrSSZ object
func (e *ErrSSZ) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 4 {
		return ssz.ErrSize
	}

	tail := buf
	var o0 uint64

	// Offset (0) 'Error'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 4 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (0) 'Error'
	{
		buf = tail[o0:]
		if len(buf) > 512 {
			return ssz.ErrBytesLength
		}
		if cap(e.Error) == 0 {
			e.Error = make([]byte, 0, len(buf))
		}
		e.Error = append(e.Error, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the ErrSSZ object
func (e *ErrSSZ) SizeSSZ() (size int) {
	size = 4

	// Field (0) 'Error'
	size += len(e.Error)

	return
}

// HashTreeRoot ssz hashes the ErrSSZ object
func (e *ErrSSZ) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(e)
}

// HashTreeRootWith ssz hashes the ErrSSZ object with a hasher
func (e *ErrSSZ) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Error'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(e.Error))
		if byteLen > 512 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(e.Error)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (512+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the ErrSSZ object
func (e *ErrSSZ) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(e)
}

// MarshalSSZ ssz marshals the Transport object
func (t *Transport) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(t)
}

// MarshalSSZTo ssz marshals the Transport object to a target array
func (t *Transport) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(40)

	// Field (0) 'Type'
	dst = ssz.MarshalUint64(dst, uint64(t.Type))

	// Field (1) 'Identifier'
	dst = append(dst, t.Identifier[:]...)

	// Offset (2) 'Data'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(t.Data)

	// Offset (3) 'Version'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(t.Version)

	// Field (2) 'Data'
	if size := len(t.Data); size > 8388608 {
		err = ssz.ErrBytesLengthFn("Transport.Data", size, 8388608)
		return
	}
	dst = append(dst, t.Data...)

	// Field (3) 'Version'
	if size := len(t.Version); size > 128 {
		err = ssz.ErrBytesLengthFn("Transport.Version", size, 128)
		return
	}
	dst = append(dst, t.Version...)

	return
}

// UnmarshalSSZ ssz unmarshals the Transport object
func (t *Transport) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 40 {
		return ssz.ErrSize
	}

	tail := buf
	var o2, o3 uint64

	// Field (0) 'Type'
	t.Type = TransportType(ssz.UnmarshallUint64(buf[0:8]))

	// Field (1) 'Identifier'
	copy(t.Identifier[:], buf[8:32])

	// Offset (2) 'Data'
	if o2 = ssz.ReadOffset(buf[32:36]); o2 > size {
		return ssz.ErrOffset
	}

	if o2 < 40 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (3) 'Version'
	if o3 = ssz.ReadOffset(buf[36:40]); o3 > size || o2 > o3 {
		return ssz.ErrOffset
	}

	// Field (2) 'Data'
	{
		buf = tail[o2:o3]
		if len(buf) > 8388608 {
			return ssz.ErrBytesLength
		}
		if cap(t.Data) == 0 {
			t.Data = make([]byte, 0, len(buf))
		}
		t.Data = append(t.Data, buf...)
	}

	// Field (3) 'Version'
	{
		buf = tail[o3:]
		if len(buf) > 128 {
			return ssz.ErrBytesLength
		}
		if cap(t.Version) == 0 {
			t.Version = make([]byte, 0, len(buf))
		}
		t.Version = append(t.Version, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Transport object
func (t *Transport) SizeSSZ() (size int) {
	size = 40

	// Field (2) 'Data'
	size += len(t.Data)

	// Field (3) 'Version'
	size += len(t.Version)

	return
}

// HashTreeRoot ssz hashes the Transport object
func (t *Transport) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(t)
}

// HashTreeRootWith ssz hashes the Transport object with a hasher
func (t *Transport) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Type'
	hh.PutUint64(uint64(t.Type))

	// Field (1) 'Identifier'
	hh.PutBytes(t.Identifier[:])

	// Field (2) 'Data'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(t.Data))
		if byteLen > 8388608 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(t.Data)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (8388608+31)/32)
	}

	// Field (3) 'Version'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(t.Version))
		if byteLen > 128 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(t.Version)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (128+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Transport object
func (t *Transport) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(t)
}

// MarshalSSZ ssz marshals the SignedTransport object
func (s *SignedTransport) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(s)
}

// MarshalSSZTo ssz marshals the SignedTransport object to a target array
func (s *SignedTransport) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Offset (0) 'Message'
	dst = ssz.WriteOffset(dst, offset)
	if s.Message == nil {
		s.Message = new(Transport)
	}
	offset += s.Message.SizeSSZ()

	// Offset (1) 'Signer'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(s.Signer)

	// Offset (2) 'Signature'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(s.Signature)

	// Field (0) 'Message'
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (1) 'Signer'
	if size := len(s.Signer); size > 2048 {
		err = ssz.ErrBytesLengthFn("SignedTransport.Signer", size, 2048)
		return
	}
	dst = append(dst, s.Signer...)

	// Field (2) 'Signature'
	if size := len(s.Signature); size > 2048 {
		err = ssz.ErrBytesLengthFn("SignedTransport.Signature", size, 2048)
		return
	}
	dst = append(dst, s.Signature...)

	return
}

// UnmarshalSSZ ssz unmarshals the SignedTransport object
func (s *SignedTransport) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1, o2 uint64

	// Offset (0) 'Message'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'Signer'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Offset (2) 'Signature'
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (0) 'Message'
	{
		buf = tail[o0:o1]
		if s.Message == nil {
			s.Message = new(Transport)
		}
		if err = s.Message.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (1) 'Signer'
	{
		buf = tail[o1:o2]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(s.Signer) == 0 {
			s.Signer = make([]byte, 0, len(buf))
		}
		s.Signer = append(s.Signer, buf...)
	}

	// Field (2) 'Signature'
	{
		buf = tail[o2:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(s.Signature) == 0 {
			s.Signature = make([]byte, 0, len(buf))
		}
		s.Signature = append(s.Signature, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the SignedTransport object
func (s *SignedTransport) SizeSSZ() (size int) {
	size = 12

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(Transport)
	}
	size += s.Message.SizeSSZ()

	// Field (1) 'Signer'
	size += len(s.Signer)

	// Field (2) 'Signature'
	size += len(s.Signature)

	return
}

// HashTreeRoot ssz hashes the SignedTransport object
func (s *SignedTransport) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(s)
}

// HashTreeRootWith ssz hashes the SignedTransport object with a hasher
func (s *SignedTransport) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Message'
	if err = s.Message.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (1) 'Signer'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(s.Signer))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(s.Signer)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	// Field (2) 'Signature'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(s.Signature))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(s.Signature)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the SignedTransport object
func (s *SignedTransport) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(s)
}

// MarshalSSZ ssz marshals the KyberMessage object
func (k *KyberMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(k)
}

// MarshalSSZTo ssz marshals the KyberMessage object to a target array
func (k *KyberMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Field (0) 'Type'
	dst = ssz.MarshalUint64(dst, uint64(k.Type))

	// Offset (1) 'Data'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(k.Data)

	// Field (1) 'Data'
	if size := len(k.Data); size > 4096 {
		err = ssz.ErrBytesLengthFn("KyberMessage.Data", size, 4096)
		return
	}
	dst = append(dst, k.Data...)

	return
}

// UnmarshalSSZ ssz unmarshals the KyberMessage object
func (k *KyberMessage) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o1 uint64

	// Field (0) 'Type'
	k.Type = TransportType(ssz.UnmarshallUint64(buf[0:8]))

	// Offset (1) 'Data'
	if o1 = ssz.ReadOffset(buf[8:12]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Data'
	{
		buf = tail[o1:]
		if len(buf) > 4096 {
			return ssz.ErrBytesLength
		}
		if cap(k.Data) == 0 {
			k.Data = make([]byte, 0, len(buf))
		}
		k.Data = append(k.Data, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the KyberMessage object
func (k *KyberMessage) SizeSSZ() (size int) {
	size = 12

	// Field (1) 'Data'
	size += len(k.Data)

	return
}

// HashTreeRoot ssz hashes the KyberMessage object
func (k *KyberMessage) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(k)
}

// HashTreeRootWith ssz hashes the KyberMessage object with a hasher
func (k *KyberMessage) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Type'
	hh.PutUint64(uint64(k.Type))

	// Field (1) 'Data'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(k.Data))
		if byteLen > 4096 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(k.Data)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (4096+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the KyberMessage object
func (k *KyberMessage) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(k)
}

// MarshalSSZ ssz marshals the Exchange object
func (e *Exchange) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(e)
}

// MarshalSSZTo ssz marshals the Exchange object to a target array
func (e *Exchange) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(8)

	// Offset (0) 'PK'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(e.PK)

	// Offset (1) 'Commits'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(e.Commits)

	// Field (0) 'PK'
	if size := len(e.PK); size > 2048 {
		err = ssz.ErrBytesLengthFn("Exchange.PK", size, 2048)
		return
	}
	dst = append(dst, e.PK...)

	// Field (1) 'Commits'
	if size := len(e.Commits); size > 2048 {
		err = ssz.ErrBytesLengthFn("Exchange.Commits", size, 2048)
		return
	}
	dst = append(dst, e.Commits...)

	return
}

// UnmarshalSSZ ssz unmarshals the Exchange object
func (e *Exchange) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 8 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1 uint64

	// Offset (0) 'PK'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 8 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'Commits'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Field (0) 'PK'
	{
		buf = tail[o0:o1]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(e.PK) == 0 {
			e.PK = make([]byte, 0, len(buf))
		}
		e.PK = append(e.PK, buf...)
	}

	// Field (1) 'Commits'
	{
		buf = tail[o1:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(e.Commits) == 0 {
			e.Commits = make([]byte, 0, len(buf))
		}
		e.Commits = append(e.Commits, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Exchange object
func (e *Exchange) SizeSSZ() (size int) {
	size = 8

	// Field (0) 'PK'
	size += len(e.PK)

	// Field (1) 'Commits'
	size += len(e.Commits)

	return
}

// HashTreeRoot ssz hashes the Exchange object
func (e *Exchange) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(e)
}

// HashTreeRootWith ssz hashes the Exchange object with a hasher
func (e *Exchange) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'PK'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(e.PK))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(e.PK)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	// Field (1) 'Commits'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(e.Commits))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(e.Commits)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Exchange object
func (e *Exchange) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(e)
}

// MarshalSSZ ssz marshals the Ping object
func (p *Ping) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(p)
}

// MarshalSSZTo ssz marshals the Ping object to a target array
func (p *Ping) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(8)

	// Offset (0) 'Operators'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(p.Operators); ii++ {
		offset += 4
		offset += p.Operators[ii].SizeSSZ()
	}

	// Offset (1) 'InitiatorPublicKey'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(p.InitiatorPublicKey)

	// Field (0) 'Operators'
	if size := len(p.Operators); size > 13 {
		err = ssz.ErrListTooBigFn("Ping.Operators", size, 13)
		return
	}
	{
		offset = 4 * len(p.Operators)
		for ii := 0; ii < len(p.Operators); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += p.Operators[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(p.Operators); ii++ {
		if dst, err = p.Operators[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (1) 'InitiatorPublicKey'
	if size := len(p.InitiatorPublicKey); size > 2048 {
		err = ssz.ErrBytesLengthFn("Ping.InitiatorPublicKey", size, 2048)
		return
	}
	dst = append(dst, p.InitiatorPublicKey...)

	return
}

// UnmarshalSSZ ssz unmarshals the Ping object
func (p *Ping) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 8 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1 uint64

	// Offset (0) 'Operators'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 8 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'InitiatorPublicKey'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Field (0) 'Operators'
	{
		buf = tail[o0:o1]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		p.Operators = make([]*spec.Operator, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if p.Operators[indx] == nil {
				p.Operators[indx] = new(spec.Operator)
			}
			if err = p.Operators[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (1) 'InitiatorPublicKey'
	{
		buf = tail[o1:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(p.InitiatorPublicKey) == 0 {
			p.InitiatorPublicKey = make([]byte, 0, len(buf))
		}
		p.InitiatorPublicKey = append(p.InitiatorPublicKey, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Ping object
func (p *Ping) SizeSSZ() (size int) {
	size = 8

	// Field (0) 'Operators'
	for ii := 0; ii < len(p.Operators); ii++ {
		size += 4
		size += p.Operators[ii].SizeSSZ()
	}

	// Field (1) 'InitiatorPublicKey'
	size += len(p.InitiatorPublicKey)

	return
}

// HashTreeRoot ssz hashes the Ping object
func (p *Ping) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(p)
}

// HashTreeRootWith ssz hashes the Ping object with a hasher
func (p *Ping) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Operators'
	{
		subIndx := hh.Index()
		num := uint64(len(p.Operators))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range p.Operators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (1) 'InitiatorPublicKey'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(p.InitiatorPublicKey))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(p.InitiatorPublicKey)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Ping object
func (p *Ping) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(p)
}

// MarshalSSZ ssz marshals the Pong object
func (p *Pong) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(p)
}

// MarshalSSZTo ssz marshals the Pong object to a target array
func (p *Pong) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Field (0) 'ID'
	dst = ssz.MarshalUint64(dst, p.ID)

	// Offset (1) 'PubKey'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(p.PubKey)

	// Field (1) 'PubKey'
	if size := len(p.PubKey); size > 2048 {
		err = ssz.ErrBytesLengthFn("Pong.PubKey", size, 2048)
		return
	}
	dst = append(dst, p.PubKey...)

	return
}

// UnmarshalSSZ ssz unmarshals the Pong object
func (p *Pong) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o1 uint64

	// Field (0) 'ID'
	p.ID = ssz.UnmarshallUint64(buf[0:8])

	// Offset (1) 'PubKey'
	if o1 = ssz.ReadOffset(buf[8:12]); o1 > size {
		return ssz.ErrOffset
	}

	if o1 < 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'PubKey'
	{
		buf = tail[o1:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(p.PubKey) == 0 {
			p.PubKey = make([]byte, 0, len(buf))
		}
		p.PubKey = append(p.PubKey, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Pong object
func (p *Pong) SizeSSZ() (size int) {
	size = 12

	// Field (1) 'PubKey'
	size += len(p.PubKey)

	return
}

// HashTreeRoot ssz hashes the Pong object
func (p *Pong) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(p)
}

// HashTreeRootWith ssz hashes the Pong object with a hasher
func (p *Pong) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'ID'
	hh.PutUint64(p.ID)

	// Field (1) 'PubKey'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(p.PubKey))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(p.PubKey)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Pong object
func (p *Pong) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(p)
}

// MarshalSSZ ssz marshals the ResultData object
func (r *ResultData) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(r)
}

// MarshalSSZTo ssz marshals the ResultData object to a target array
func (r *ResultData) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(40)

	// Offset (0) 'Operators'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(r.Operators); ii++ {
		offset += 4
		offset += r.Operators[ii].SizeSSZ()
	}

	// Field (1) 'Identifier'
	dst = append(dst, r.Identifier[:]...)

	// Offset (2) 'DepositData'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(r.DepositData)

	// Offset (3) 'KeysharesData'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(r.KeysharesData)

	// Offset (4) 'Proofs'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(r.Proofs)

	// Field (0) 'Operators'
	if size := len(r.Operators); size > 13 {
		err = ssz.ErrListTooBigFn("ResultData.Operators", size, 13)
		return
	}
	{
		offset = 4 * len(r.Operators)
		for ii := 0; ii < len(r.Operators); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += r.Operators[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(r.Operators); ii++ {
		if dst, err = r.Operators[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (2) 'DepositData'
	if size := len(r.DepositData); size > 8192 {
		err = ssz.ErrBytesLengthFn("ResultData.DepositData", size, 8192)
		return
	}
	dst = append(dst, r.DepositData...)

	// Field (3) 'KeysharesData'
	if size := len(r.KeysharesData); size > 32768 {
		err = ssz.ErrBytesLengthFn("ResultData.KeysharesData", size, 32768)
		return
	}
	dst = append(dst, r.KeysharesData...)

	// Field (4) 'Proofs'
	if size := len(r.Proofs); size > 32768 {
		err = ssz.ErrBytesLengthFn("ResultData.Proofs", size, 32768)
		return
	}
	dst = append(dst, r.Proofs...)

	return
}

// UnmarshalSSZ ssz unmarshals the ResultData object
func (r *ResultData) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 40 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o2, o3, o4 uint64

	// Offset (0) 'Operators'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 40 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Identifier'
	copy(r.Identifier[:], buf[4:28])

	// Offset (2) 'DepositData'
	if o2 = ssz.ReadOffset(buf[28:32]); o2 > size || o0 > o2 {
		return ssz.ErrOffset
	}

	// Offset (3) 'KeysharesData'
	if o3 = ssz.ReadOffset(buf[32:36]); o3 > size || o2 > o3 {
		return ssz.ErrOffset
	}

	// Offset (4) 'Proofs'
	if o4 = ssz.ReadOffset(buf[36:40]); o4 > size || o3 > o4 {
		return ssz.ErrOffset
	}

	// Field (0) 'Operators'
	{
		buf = tail[o0:o2]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		r.Operators = make([]*spec.Operator, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if r.Operators[indx] == nil {
				r.Operators[indx] = new(spec.Operator)
			}
			if err = r.Operators[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (2) 'DepositData'
	{
		buf = tail[o2:o3]
		if len(buf) > 8192 {
			return ssz.ErrBytesLength
		}
		if cap(r.DepositData) == 0 {
			r.DepositData = make([]byte, 0, len(buf))
		}
		r.DepositData = append(r.DepositData, buf...)
	}

	// Field (3) 'KeysharesData'
	{
		buf = tail[o3:o4]
		if len(buf) > 32768 {
			return ssz.ErrBytesLength
		}
		if cap(r.KeysharesData) == 0 {
			r.KeysharesData = make([]byte, 0, len(buf))
		}
		r.KeysharesData = append(r.KeysharesData, buf...)
	}

	// Field (4) 'Proofs'
	{
		buf = tail[o4:]
		if len(buf) > 32768 {
			return ssz.ErrBytesLength
		}
		if cap(r.Proofs) == 0 {
			r.Proofs = make([]byte, 0, len(buf))
		}
		r.Proofs = append(r.Proofs, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the ResultData object
func (r *ResultData) SizeSSZ() (size int) {
	size = 40

	// Field (0) 'Operators'
	for ii := 0; ii < len(r.Operators); ii++ {
		size += 4
		size += r.Operators[ii].SizeSSZ()
	}

	// Field (2) 'DepositData'
	size += len(r.DepositData)

	// Field (3) 'KeysharesData'
	size += len(r.KeysharesData)

	// Field (4) 'Proofs'
	size += len(r.Proofs)

	return
}

// HashTreeRoot ssz hashes the ResultData object
func (r *ResultData) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(r)
}

// HashTreeRootWith ssz hashes the ResultData object with a hasher
func (r *ResultData) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Operators'
	{
		subIndx := hh.Index()
		num := uint64(len(r.Operators))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range r.Operators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (1) 'Identifier'
	hh.PutBytes(r.Identifier[:])

	// Field (2) 'DepositData'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(r.DepositData))
		if byteLen > 8192 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(r.DepositData)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (8192+31)/32)
	}

	// Field (3) 'KeysharesData'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(r.KeysharesData))
		if byteLen > 32768 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(r.KeysharesData)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32768+31)/32)
	}

	// Field (4) 'Proofs'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(r.Proofs))
		if byteLen > 32768 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(r.Proofs)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32768+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the ResultData object
func (r *ResultData) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(r)
}

// MarshalSSZ ssz marshals the ResignMessage object
func (r *ResignMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(r)
}

// MarshalSSZTo ssz marshals the ResignMessage object to a target array
func (r *ResignMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Offset (0) 'Operators'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(r.Operators); ii++ {
		offset += 4
		offset += r.Operators[ii].SizeSSZ()
	}

	// Offset (1) 'Resign'
	dst = ssz.WriteOffset(dst, offset)
	if r.Resign == nil {
		r.Resign = new(spec.Resign)
	}
	offset += r.Resign.SizeSSZ()

	// Offset (2) 'Proofs'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(r.Proofs); ii++ {
		offset += 4
		offset += r.Proofs[ii].SizeSSZ()
	}

	// Field (0) 'Operators'
	if size := len(r.Operators); size > 13 {
		err = ssz.ErrListTooBigFn("ResignMessage.Operators", size, 13)
		return
	}
	{
		offset = 4 * len(r.Operators)
		for ii := 0; ii < len(r.Operators); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += r.Operators[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(r.Operators); ii++ {
		if dst, err = r.Operators[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (1) 'Resign'
	if dst, err = r.Resign.MarshalSSZTo(dst); err != nil {
		return
	}

	// Field (2) 'Proofs'
	if size := len(r.Proofs); size > 13 {
		err = ssz.ErrListTooBigFn("ResignMessage.Proofs", size, 13)
		return
	}
	{
		offset = 4 * len(r.Proofs)
		for ii := 0; ii < len(r.Proofs); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += r.Proofs[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(r.Proofs); ii++ {
		if dst, err = r.Proofs[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	return
}

// UnmarshalSSZ ssz unmarshals the ResignMessage object
func (r *ResignMessage) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1, o2 uint64

	// Offset (0) 'Operators'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 12 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'Resign'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Offset (2) 'Proofs'
	if o2 = ssz.ReadOffset(buf[8:12]); o2 > size || o1 > o2 {
		return ssz.ErrOffset
	}

	// Field (0) 'Operators'
	{
		buf = tail[o0:o1]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		r.Operators = make([]*spec.Operator, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if r.Operators[indx] == nil {
				r.Operators[indx] = new(spec.Operator)
			}
			if err = r.Operators[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (1) 'Resign'
	{
		buf = tail[o1:o2]
		if r.Resign == nil {
			r.Resign = new(spec.Resign)
		}
		if err = r.Resign.UnmarshalSSZ(buf); err != nil {
			return err
		}
	}

	// Field (2) 'Proofs'
	{
		buf = tail[o2:]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		r.Proofs = make([]*spec.SignedProof, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if r.Proofs[indx] == nil {
				r.Proofs[indx] = new(spec.SignedProof)
			}
			if err = r.Proofs[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the ResignMessage object
func (r *ResignMessage) SizeSSZ() (size int) {
	size = 12

	// Field (0) 'Operators'
	for ii := 0; ii < len(r.Operators); ii++ {
		size += 4
		size += r.Operators[ii].SizeSSZ()
	}

	// Field (1) 'Resign'
	if r.Resign == nil {
		r.Resign = new(spec.Resign)
	}
	size += r.Resign.SizeSSZ()

	// Field (2) 'Proofs'
	for ii := 0; ii < len(r.Proofs); ii++ {
		size += 4
		size += r.Proofs[ii].SizeSSZ()
	}

	return
}

// HashTreeRoot ssz hashes the ResignMessage object
func (r *ResignMessage) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(r)
}

// HashTreeRootWith ssz hashes the ResignMessage object with a hasher
func (r *ResignMessage) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Operators'
	{
		subIndx := hh.Index()
		num := uint64(len(r.Operators))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range r.Operators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (1) 'Resign'
	if err = r.Resign.HashTreeRootWith(hh); err != nil {
		return
	}

	// Field (2) 'Proofs'
	{
		subIndx := hh.Index()
		num := uint64(len(r.Proofs))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range r.Proofs {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the ResignMessage object
func (r *ResignMessage) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(r)
}