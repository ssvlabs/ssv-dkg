// Code generated by fastssz. DO NOT EDIT.
// Hash: b914c35429e0d34e52f00d7f8c5de8dcc0ee1dc294d9118d79dc182fe1ec0785
// Version: 0.1.3
package wire

import (
	ssz "github.com/ferranbt/fastssz"
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
	offset := int(36)

	// Field (0) 'Type'
	dst = ssz.MarshalUint64(dst, uint64(t.Type))

	// Field (1) 'Identifier'
	dst = append(dst, t.Identifier[:]...)

	// Offset (2) 'Data'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(t.Data)

	// Field (2) 'Data'
	if size := len(t.Data); size > 8388608 {
		err = ssz.ErrBytesLengthFn("Transport.Data", size, 8388608)
		return
	}
	dst = append(dst, t.Data...)

	return
}

// UnmarshalSSZ ssz unmarshals the Transport object
func (t *Transport) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 36 {
		return ssz.ErrSize
	}

	tail := buf
	var o2 uint64

	// Field (0) 'Type'
	t.Type = TransportType(ssz.UnmarshallUint64(buf[0:8]))

	// Field (1) 'Identifier'
	copy(t.Identifier[:], buf[8:32])

	// Offset (2) 'Data'
	if o2 = ssz.ReadOffset(buf[32:36]); o2 > size {
		return ssz.ErrOffset
	}

	if o2 < 36 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (2) 'Data'
	{
		buf = tail[o2:]
		if len(buf) > 8388608 {
			return ssz.ErrBytesLength
		}
		if cap(t.Data) == 0 {
			t.Data = make([]byte, 0, len(buf))
		}
		t.Data = append(t.Data, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Transport object
func (t *Transport) SizeSSZ() (size int) {
	size = 36

	// Field (2) 'Data'
	size += len(t.Data)

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
	offset := int(16)

	// Offset (0) 'Message'
	dst = ssz.WriteOffset(dst, offset)
	if s.Message == nil {
		s.Message = new(Transport)
	}
	offset += s.Message.SizeSSZ()

	// Field (1) 'Signer'
	dst = ssz.MarshalUint64(dst, s.Signer)

	// Offset (2) 'Signature'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(s.Signature)

	// Field (0) 'Message'
	if dst, err = s.Message.MarshalSSZTo(dst); err != nil {
		return
	}

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
	if size < 16 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o2 uint64

	// Offset (0) 'Message'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 16 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'Signer'
	s.Signer = ssz.UnmarshallUint64(buf[4:12])

	// Offset (2) 'Signature'
	if o2 = ssz.ReadOffset(buf[12:16]); o2 > size || o0 > o2 {
		return ssz.ErrOffset
	}

	// Field (0) 'Message'
	{
		buf = tail[o0:o2]
		if s.Message == nil {
			s.Message = new(Transport)
		}
		if err = s.Message.UnmarshalSSZ(buf); err != nil {
			return err
		}
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
	size = 16

	// Field (0) 'Message'
	if s.Message == nil {
		s.Message = new(Transport)
	}
	size += s.Message.SizeSSZ()

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
	hh.PutUint64(s.Signer)

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

// MarshalSSZ ssz marshals the ReshareKyberMessage object
func (r *ReshareKyberMessage) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(r)
}

// MarshalSSZTo ssz marshals the ReshareKyberMessage object to a target array
func (r *ReshareKyberMessage) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Field (0) 'Type'
	dst = ssz.MarshalUint64(dst, uint64(r.Type))

	// Offset (1) 'Data'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(r.Data)

	// Field (1) 'Data'
	if size := len(r.Data); size > 4096 {
		err = ssz.ErrBytesLengthFn("ReshareKyberMessage.Data", size, 4096)
		return
	}
	dst = append(dst, r.Data...)

	return
}

// UnmarshalSSZ ssz unmarshals the ReshareKyberMessage object
func (r *ReshareKyberMessage) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o1 uint64

	// Field (0) 'Type'
	r.Type = TransportType(ssz.UnmarshallUint64(buf[0:8]))

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
		if cap(r.Data) == 0 {
			r.Data = make([]byte, 0, len(buf))
		}
		r.Data = append(r.Data, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the ReshareKyberMessage object
func (r *ReshareKyberMessage) SizeSSZ() (size int) {
	size = 12

	// Field (1) 'Data'
	size += len(r.Data)

	return
}

// HashTreeRoot ssz hashes the ReshareKyberMessage object
func (r *ReshareKyberMessage) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(r)
}

// HashTreeRootWith ssz hashes the ReshareKyberMessage object with a hasher
func (r *ReshareKyberMessage) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Type'
	hh.PutUint64(uint64(r.Type))

	// Field (1) 'Data'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(r.Data))
		if byteLen > 4096 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(r.Data)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (4096+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the ReshareKyberMessage object
func (r *ReshareKyberMessage) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(r)
}

// MarshalSSZ ssz marshals the Operator object
func (o *Operator) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(o)
}

// MarshalSSZTo ssz marshals the Operator object to a target array
func (o *Operator) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(12)

	// Field (0) 'ID'
	dst = ssz.MarshalUint64(dst, o.ID)

	// Offset (1) 'PubKey'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(o.PubKey)

	// Field (1) 'PubKey'
	if size := len(o.PubKey); size > 2048 {
		err = ssz.ErrBytesLengthFn("Operator.PubKey", size, 2048)
		return
	}
	dst = append(dst, o.PubKey...)

	return
}

// UnmarshalSSZ ssz unmarshals the Operator object
func (o *Operator) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 12 {
		return ssz.ErrSize
	}

	tail := buf
	var o1 uint64

	// Field (0) 'ID'
	o.ID = ssz.UnmarshallUint64(buf[0:8])

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
		if cap(o.PubKey) == 0 {
			o.PubKey = make([]byte, 0, len(buf))
		}
		o.PubKey = append(o.PubKey, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Operator object
func (o *Operator) SizeSSZ() (size int) {
	size = 12

	// Field (1) 'PubKey'
	size += len(o.PubKey)

	return
}

// HashTreeRoot ssz hashes the Operator object
func (o *Operator) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(o)
}

// HashTreeRootWith ssz hashes the Operator object with a hasher
func (o *Operator) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'ID'
	hh.PutUint64(o.ID)

	// Field (1) 'PubKey'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(o.PubKey))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(o.PubKey)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Operator object
func (o *Operator) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(o)
}

// MarshalSSZ ssz marshals the Init object
func (i *Init) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(i)
}

// MarshalSSZTo ssz marshals the Init object to a target array
func (i *Init) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(52)

	// Offset (0) 'Operators'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(i.Operators); ii++ {
		offset += 4
		offset += i.Operators[ii].SizeSSZ()
	}

	// Field (1) 'T'
	dst = ssz.MarshalUint64(dst, i.T)

	// Offset (2) 'WithdrawalCredentials'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(i.WithdrawalCredentials)

	// Field (3) 'Fork'
	dst = append(dst, i.Fork[:]...)

	// Field (4) 'Owner'
	dst = append(dst, i.Owner[:]...)

	// Field (5) 'Nonce'
	dst = ssz.MarshalUint64(dst, i.Nonce)

	// Offset (6) 'InitiatorPublicKey'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(i.InitiatorPublicKey)

	// Field (0) 'Operators'
	if size := len(i.Operators); size > 13 {
		err = ssz.ErrListTooBigFn("Init.Operators", size, 13)
		return
	}
	{
		offset = 4 * len(i.Operators)
		for ii := 0; ii < len(i.Operators); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += i.Operators[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(i.Operators); ii++ {
		if dst, err = i.Operators[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (2) 'WithdrawalCredentials'
	if size := len(i.WithdrawalCredentials); size > 32 {
		err = ssz.ErrBytesLengthFn("Init.WithdrawalCredentials", size, 32)
		return
	}
	dst = append(dst, i.WithdrawalCredentials...)

	// Field (6) 'InitiatorPublicKey'
	if size := len(i.InitiatorPublicKey); size > 2048 {
		err = ssz.ErrBytesLengthFn("Init.InitiatorPublicKey", size, 2048)
		return
	}
	dst = append(dst, i.InitiatorPublicKey...)

	return
}

// UnmarshalSSZ ssz unmarshals the Init object
func (i *Init) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 52 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o2, o6 uint64

	// Offset (0) 'Operators'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 52 {
		return ssz.ErrInvalidVariableOffset
	}

	// Field (1) 'T'
	i.T = ssz.UnmarshallUint64(buf[4:12])

	// Offset (2) 'WithdrawalCredentials'
	if o2 = ssz.ReadOffset(buf[12:16]); o2 > size || o0 > o2 {
		return ssz.ErrOffset
	}

	// Field (3) 'Fork'
	copy(i.Fork[:], buf[16:20])

	// Field (4) 'Owner'
	copy(i.Owner[:], buf[20:40])

	// Field (5) 'Nonce'
	i.Nonce = ssz.UnmarshallUint64(buf[40:48])

	// Offset (6) 'InitiatorPublicKey'
	if o6 = ssz.ReadOffset(buf[48:52]); o6 > size || o2 > o6 {
		return ssz.ErrOffset
	}

	// Field (0) 'Operators'
	{
		buf = tail[o0:o2]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		i.Operators = make([]*Operator, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if i.Operators[indx] == nil {
				i.Operators[indx] = new(Operator)
			}
			if err = i.Operators[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (2) 'WithdrawalCredentials'
	{
		buf = tail[o2:o6]
		if len(buf) > 32 {
			return ssz.ErrBytesLength
		}
		if cap(i.WithdrawalCredentials) == 0 {
			i.WithdrawalCredentials = make([]byte, 0, len(buf))
		}
		i.WithdrawalCredentials = append(i.WithdrawalCredentials, buf...)
	}

	// Field (6) 'InitiatorPublicKey'
	{
		buf = tail[o6:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(i.InitiatorPublicKey) == 0 {
			i.InitiatorPublicKey = make([]byte, 0, len(buf))
		}
		i.InitiatorPublicKey = append(i.InitiatorPublicKey, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Init object
func (i *Init) SizeSSZ() (size int) {
	size = 52

	// Field (0) 'Operators'
	for ii := 0; ii < len(i.Operators); ii++ {
		size += 4
		size += i.Operators[ii].SizeSSZ()
	}

	// Field (2) 'WithdrawalCredentials'
	size += len(i.WithdrawalCredentials)

	// Field (6) 'InitiatorPublicKey'
	size += len(i.InitiatorPublicKey)

	return
}

// HashTreeRoot ssz hashes the Init object
func (i *Init) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(i)
}

// HashTreeRootWith ssz hashes the Init object with a hasher
func (i *Init) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'Operators'
	{
		subIndx := hh.Index()
		num := uint64(len(i.Operators))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range i.Operators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (1) 'T'
	hh.PutUint64(i.T)

	// Field (2) 'WithdrawalCredentials'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(i.WithdrawalCredentials))
		if byteLen > 32 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(i.WithdrawalCredentials)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (32+31)/32)
	}

	// Field (3) 'Fork'
	hh.PutBytes(i.Fork[:])

	// Field (4) 'Owner'
	hh.PutBytes(i.Owner[:])

	// Field (5) 'Nonce'
	hh.PutUint64(i.Nonce)

	// Field (6) 'InitiatorPublicKey'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(i.InitiatorPublicKey))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(i.InitiatorPublicKey)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Init object
func (i *Init) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(i)
}

// MarshalSSZ ssz marshals the Reshare object
func (r *Reshare) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(r)
}

// MarshalSSZTo ssz marshals the Reshare object to a target array
func (r *Reshare) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(80)

	// Offset (0) 'OldOperators'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(r.OldOperators); ii++ {
		offset += 4
		offset += r.OldOperators[ii].SizeSSZ()
	}

	// Offset (1) 'NewOperators'
	dst = ssz.WriteOffset(dst, offset)
	for ii := 0; ii < len(r.NewOperators); ii++ {
		offset += 4
		offset += r.NewOperators[ii].SizeSSZ()
	}

	// Field (2) 'OldT'
	dst = ssz.MarshalUint64(dst, r.OldT)

	// Field (3) 'NewT'
	dst = ssz.MarshalUint64(dst, r.NewT)

	// Offset (4) 'InitiatorPublicKey'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(r.InitiatorPublicKey)

	// Field (5) 'OldID'
	dst = append(dst, r.OldID[:]...)

	// Field (6) 'Owner'
	dst = append(dst, r.Owner[:]...)

	// Field (7) 'Nonce'
	dst = ssz.MarshalUint64(dst, r.Nonce)

	// Field (0) 'OldOperators'
	if size := len(r.OldOperators); size > 13 {
		err = ssz.ErrListTooBigFn("Reshare.OldOperators", size, 13)
		return
	}
	{
		offset = 4 * len(r.OldOperators)
		for ii := 0; ii < len(r.OldOperators); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += r.OldOperators[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(r.OldOperators); ii++ {
		if dst, err = r.OldOperators[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (1) 'NewOperators'
	if size := len(r.NewOperators); size > 13 {
		err = ssz.ErrListTooBigFn("Reshare.NewOperators", size, 13)
		return
	}
	{
		offset = 4 * len(r.NewOperators)
		for ii := 0; ii < len(r.NewOperators); ii++ {
			dst = ssz.WriteOffset(dst, offset)
			offset += r.NewOperators[ii].SizeSSZ()
		}
	}
	for ii := 0; ii < len(r.NewOperators); ii++ {
		if dst, err = r.NewOperators[ii].MarshalSSZTo(dst); err != nil {
			return
		}
	}

	// Field (4) 'InitiatorPublicKey'
	if size := len(r.InitiatorPublicKey); size > 2048 {
		err = ssz.ErrBytesLengthFn("Reshare.InitiatorPublicKey", size, 2048)
		return
	}
	dst = append(dst, r.InitiatorPublicKey...)

	return
}

// UnmarshalSSZ ssz unmarshals the Reshare object
func (r *Reshare) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 80 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1, o4 uint64

	// Offset (0) 'OldOperators'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 80 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'NewOperators'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Field (2) 'OldT'
	r.OldT = ssz.UnmarshallUint64(buf[8:16])

	// Field (3) 'NewT'
	r.NewT = ssz.UnmarshallUint64(buf[16:24])

	// Offset (4) 'InitiatorPublicKey'
	if o4 = ssz.ReadOffset(buf[24:28]); o4 > size || o1 > o4 {
		return ssz.ErrOffset
	}

	// Field (5) 'OldID'
	copy(r.OldID[:], buf[28:52])

	// Field (6) 'Owner'
	copy(r.Owner[:], buf[52:72])

	// Field (7) 'Nonce'
	r.Nonce = ssz.UnmarshallUint64(buf[72:80])

	// Field (0) 'OldOperators'
	{
		buf = tail[o0:o1]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		r.OldOperators = make([]*Operator, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if r.OldOperators[indx] == nil {
				r.OldOperators[indx] = new(Operator)
			}
			if err = r.OldOperators[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (1) 'NewOperators'
	{
		buf = tail[o1:o4]
		num, err := ssz.DecodeDynamicLength(buf, 13)
		if err != nil {
			return err
		}
		r.NewOperators = make([]*Operator, num)
		err = ssz.UnmarshalDynamic(buf, num, func(indx int, buf []byte) (err error) {
			if r.NewOperators[indx] == nil {
				r.NewOperators[indx] = new(Operator)
			}
			if err = r.NewOperators[indx].UnmarshalSSZ(buf); err != nil {
				return err
			}
			return nil
		})
		if err != nil {
			return err
		}
	}

	// Field (4) 'InitiatorPublicKey'
	{
		buf = tail[o4:]
		if len(buf) > 2048 {
			return ssz.ErrBytesLength
		}
		if cap(r.InitiatorPublicKey) == 0 {
			r.InitiatorPublicKey = make([]byte, 0, len(buf))
		}
		r.InitiatorPublicKey = append(r.InitiatorPublicKey, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Reshare object
func (r *Reshare) SizeSSZ() (size int) {
	size = 80

	// Field (0) 'OldOperators'
	for ii := 0; ii < len(r.OldOperators); ii++ {
		size += 4
		size += r.OldOperators[ii].SizeSSZ()
	}

	// Field (1) 'NewOperators'
	for ii := 0; ii < len(r.NewOperators); ii++ {
		size += 4
		size += r.NewOperators[ii].SizeSSZ()
	}

	// Field (4) 'InitiatorPublicKey'
	size += len(r.InitiatorPublicKey)

	return
}

// HashTreeRoot ssz hashes the Reshare object
func (r *Reshare) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(r)
}

// HashTreeRootWith ssz hashes the Reshare object with a hasher
func (r *Reshare) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'OldOperators'
	{
		subIndx := hh.Index()
		num := uint64(len(r.OldOperators))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range r.OldOperators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (1) 'NewOperators'
	{
		subIndx := hh.Index()
		num := uint64(len(r.NewOperators))
		if num > 13 {
			err = ssz.ErrIncorrectListSize
			return
		}
		for _, elem := range r.NewOperators {
			if err = elem.HashTreeRootWith(hh); err != nil {
				return
			}
		}
		hh.MerkleizeWithMixin(subIndx, num, 13)
	}

	// Field (2) 'OldT'
	hh.PutUint64(r.OldT)

	// Field (3) 'NewT'
	hh.PutUint64(r.NewT)

	// Field (4) 'InitiatorPublicKey'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(r.InitiatorPublicKey))
		if byteLen > 2048 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(r.InitiatorPublicKey)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (2048+31)/32)
	}

	// Field (5) 'OldID'
	hh.PutBytes(r.OldID[:])

	// Field (6) 'Owner'
	hh.PutBytes(r.Owner[:])

	// Field (7) 'Nonce'
	hh.PutUint64(r.Nonce)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Reshare object
func (r *Reshare) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(r)
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

// MarshalSSZ ssz marshals the Output object
func (o *Output) MarshalSSZ() ([]byte, error) {
	return ssz.MarshalSSZ(o)
}

// MarshalSSZTo ssz marshals the Output object to a target array
func (o *Output) MarshalSSZTo(buf []byte) (dst []byte, err error) {
	dst = buf
	offset := int(152)

	// Offset (0) 'EncryptedShare'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(o.EncryptedShare)

	// Offset (1) 'SharePK'
	dst = ssz.WriteOffset(dst, offset)
	offset += len(o.SharePK)

	// Field (2) 'ValidatorPK'
	if size := len(o.ValidatorPK); size != 48 {
		err = ssz.ErrBytesLengthFn("Output.ValidatorPK", size, 48)
		return
	}
	dst = append(dst, o.ValidatorPK...)

	// Field (3) 'DepositDataPartialSignature'
	if size := len(o.DepositDataPartialSignature); size != 96 {
		err = ssz.ErrBytesLengthFn("Output.DepositDataPartialSignature", size, 96)
		return
	}
	dst = append(dst, o.DepositDataPartialSignature...)

	// Field (0) 'EncryptedShare'
	if size := len(o.EncryptedShare); size > 4096 {
		err = ssz.ErrBytesLengthFn("Output.EncryptedShare", size, 4096)
		return
	}
	dst = append(dst, o.EncryptedShare...)

	// Field (1) 'SharePK'
	if size := len(o.SharePK); size > 4096 {
		err = ssz.ErrBytesLengthFn("Output.SharePK", size, 4096)
		return
	}
	dst = append(dst, o.SharePK...)

	return
}

// UnmarshalSSZ ssz unmarshals the Output object
func (o *Output) UnmarshalSSZ(buf []byte) error {
	var err error
	size := uint64(len(buf))
	if size < 152 {
		return ssz.ErrSize
	}

	tail := buf
	var o0, o1 uint64

	// Offset (0) 'EncryptedShare'
	if o0 = ssz.ReadOffset(buf[0:4]); o0 > size {
		return ssz.ErrOffset
	}

	if o0 < 152 {
		return ssz.ErrInvalidVariableOffset
	}

	// Offset (1) 'SharePK'
	if o1 = ssz.ReadOffset(buf[4:8]); o1 > size || o0 > o1 {
		return ssz.ErrOffset
	}

	// Field (2) 'ValidatorPK'
	if cap(o.ValidatorPK) == 0 {
		o.ValidatorPK = make([]byte, 0, len(buf[8:56]))
	}
	o.ValidatorPK = append(o.ValidatorPK, buf[8:56]...)

	// Field (3) 'DepositDataPartialSignature'
	if cap(o.DepositDataPartialSignature) == 0 {
		o.DepositDataPartialSignature = make([]byte, 0, len(buf[56:152]))
	}
	o.DepositDataPartialSignature = append(o.DepositDataPartialSignature, buf[56:152]...)

	// Field (0) 'EncryptedShare'
	{
		buf = tail[o0:o1]
		if len(buf) > 4096 {
			return ssz.ErrBytesLength
		}
		if cap(o.EncryptedShare) == 0 {
			o.EncryptedShare = make([]byte, 0, len(buf))
		}
		o.EncryptedShare = append(o.EncryptedShare, buf...)
	}

	// Field (1) 'SharePK'
	{
		buf = tail[o1:]
		if len(buf) > 4096 {
			return ssz.ErrBytesLength
		}
		if cap(o.SharePK) == 0 {
			o.SharePK = make([]byte, 0, len(buf))
		}
		o.SharePK = append(o.SharePK, buf...)
	}
	return err
}

// SizeSSZ returns the ssz encoded size in bytes for the Output object
func (o *Output) SizeSSZ() (size int) {
	size = 152

	// Field (0) 'EncryptedShare'
	size += len(o.EncryptedShare)

	// Field (1) 'SharePK'
	size += len(o.SharePK)

	return
}

// HashTreeRoot ssz hashes the Output object
func (o *Output) HashTreeRoot() ([32]byte, error) {
	return ssz.HashWithDefaultHasher(o)
}

// HashTreeRootWith ssz hashes the Output object with a hasher
func (o *Output) HashTreeRootWith(hh ssz.HashWalker) (err error) {
	indx := hh.Index()

	// Field (0) 'EncryptedShare'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(o.EncryptedShare))
		if byteLen > 4096 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(o.EncryptedShare)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (4096+31)/32)
	}

	// Field (1) 'SharePK'
	{
		elemIndx := hh.Index()
		byteLen := uint64(len(o.SharePK))
		if byteLen > 4096 {
			err = ssz.ErrIncorrectListSize
			return
		}
		hh.Append(o.SharePK)
		hh.MerkleizeWithMixin(elemIndx, byteLen, (4096+31)/32)
	}

	// Field (2) 'ValidatorPK'
	if size := len(o.ValidatorPK); size != 48 {
		err = ssz.ErrBytesLengthFn("Output.ValidatorPK", size, 48)
		return
	}
	hh.PutBytes(o.ValidatorPK)

	// Field (3) 'DepositDataPartialSignature'
	if size := len(o.DepositDataPartialSignature); size != 96 {
		err = ssz.ErrBytesLengthFn("Output.DepositDataPartialSignature", size, 96)
		return
	}
	hh.PutBytes(o.DepositDataPartialSignature)

	hh.Merkleize(indx)
	return
}

// GetTree ssz hashes the Output object
func (o *Output) GetTree() (*ssz.Node, error) {
	return ssz.ProofTree(o)
}
