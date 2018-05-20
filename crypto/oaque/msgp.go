package oaque

import (
	"errors"

	"github.com/tinylib/msgp/msgp"
)

// EncodeMsg allows objects to be msgp encoded
func (o *Params) EncodeMsg(w *msgp.Writer) error {
	return encodeMsg(o, w)
}

// MarshalMsg allows objects to be msgp marshalled
func (o *Params) MarshalMsg(onto []byte) ([]byte, error) {
	return marshalMsg(o, onto)
}

// UnmarshalMsg allows objects to be msgp unmarshalled
func (o *Params) UnmarshalMsg(from []byte) ([]byte, error) {
	return unmarshalMsg(o, from)
}
func (o *Params) Msgsize() int {
	hasSigElem := 0
	if o.HSig != nil {
		hasSigElem = 1
	}
	return ((6 + hasSigElem + len(o.H)) << geShift) + 1 + 6
}

// DecodeMsg allows objects to be msgp decoded
func (o *Params) DecodeMsg(r *msgp.Reader) error {
	return decodeMsg(o, r)
}

// EncodeMsg allows objects to be msgp encoded
func (o *MasterKey) EncodeMsg(w *msgp.Writer) error {
	return encodeMsg(o, w)
}

// MarshalMsg allows objects to be msgp marshalled
func (o *MasterKey) MarshalMsg(onto []byte) ([]byte, error) {
	return marshalMsg(o, onto)
}

// UnmarshalMsg allows objects to be msgp unmarshalled
func (o *MasterKey) UnmarshalMsg(from []byte) ([]byte, error) {
	return unmarshalMsg(o, from)
}

// DecodeMsg allows objects to be msgp decoded
func (o *MasterKey) DecodeMsg(r *msgp.Reader) error {
	return decodeMsg(o, r)
}
func (o *MasterKey) Msgsize() int {
	return 64 + 6
}

// EncodeMsg allows objects to be msgp encoded
func (o *PrivateKey) EncodeMsg(w *msgp.Writer) error {
	return encodeMsg(o, w)
}

// MarshalMsg allows objects to be msgp marshalled
func (o *PrivateKey) MarshalMsg(onto []byte) ([]byte, error) {
	return marshalMsg(o, onto)
}

// UnmarshalMsg allows objects to be msgp unmarshalled
func (o *PrivateKey) UnmarshalMsg(from []byte) ([]byte, error) {
	return unmarshalMsg(o, from)
}

// DecodeMsg allows objects to be msgp decoded
func (o *PrivateKey) DecodeMsg(r *msgp.Reader) error {
	return decodeMsg(o, r)
}

func (o *PrivateKey) Msgsize() int {
	hasSigElem := 0
	if o.BSig != nil {
		hasSigElem = 1
	}
	return (3+len(o.B)+hasSigElem)<<geShift + len(o.B)*attributeIndexSize + 1 + 6
}

// EncodeMsg allows objects to be msgp encoded
func (o *Ciphertext) EncodeMsg(w *msgp.Writer) error {
	return encodeMsg(o, w)
}

// MarshalMsg allows objects to be msgp marshalled
func (o *Ciphertext) MarshalMsg(onto []byte) ([]byte, error) {
	return marshalMsg(o, onto)
}

// UnmarshalMsg allows objects to be msgp unmarshalled
func (o *Ciphertext) UnmarshalMsg(from []byte) ([]byte, error) {
	return unmarshalMsg(o, from)
}

// DecodeMsg allows objects to be msgp decoded
func (o *Ciphertext) DecodeMsg(r *msgp.Reader) error {
	return decodeMsg(o, r)
}

func (o *Ciphertext) Msgsize() int {
	return 5 << geShift
}

// EncodeMsg allows objects to be msgp encoded
func (o *Signature) EncodeMsg(w *msgp.Writer) error {
	return encodeMsg(o, w)
}

// MarshalMsg allows objects to be msgp marshalled
func (o *Signature) MarshalMsg(onto []byte) ([]byte, error) {
	return marshalMsg(o, onto)
}

// UnmarshalMsg allows objects to be msgp unmarshalled
func (o *Signature) UnmarshalMsg(from []byte) ([]byte, error) {
	return unmarshalMsg(o, from)
}

func (o *Signature) Msgsize() int {
	return 3 << geShift
}

// DecodeMsg allows objects to be msgp decoded
func (o *Signature) DecodeMsg(r *msgp.Reader) error {
	return decodeMsg(o, r)
}

type marshalable interface {
	Unmarshal(marshalled []byte) bool
	Marshal() []byte
}

func unmarshalMsg(t marshalable, from []byte) ([]byte, error) {
	val, rem, err := msgp.ReadBytesBytes(from, nil)
	if err != nil {
		return nil, err
	}
	if !t.Unmarshal(val) {
		return nil, errors.New("could not unmarshal object")
	}
	return rem, nil
}
func marshalMsg(t marshalable, onto []byte) ([]byte, error) {
	return msgp.AppendBytes(onto, t.Marshal()), nil
}
func encodeMsg(t marshalable, w *msgp.Writer) error {
	return w.WriteBytes(t.Marshal())
}
func decodeMsg(t marshalable, r *msgp.Reader) error {
	marshalled, err := r.ReadBytes(nil)
	if err != nil {
		return err
	}
	if !t.Unmarshal(marshalled) {
		return errors.New("could not unmarshal object")
	}
	return nil
}
