package oaque

// NOTE: THIS FILE WAS PRODUCED BY THE
// MSGP CODE GENERATION TOOL (github.com/tinylib/msgp)
// DO NOT EDIT

import (
	"github.com/tinylib/msgp/msgp"
)

// DecodeMsg implements msgp.Decodable
func (z *TestMessage) DecodeMsg(dc *msgp.Reader) (err error) {
	var field []byte
	_ = field
	var zxvk uint32
	zxvk, err = dc.ReadMapHeader()
	if err != nil {
		return
	}
	for zxvk > 0 {
		zxvk--
		field, err = dc.ReadMapKeyPtr()
		if err != nil {
			return
		}
		switch msgp.UnsafeString(field) {
		case "Params":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Params = nil
			} else {
				if z.Params == nil {
					z.Params = new(Params)
				}
				err = z.Params.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "MasterKey":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.MasterKey = nil
			} else {
				if z.MasterKey == nil {
					z.MasterKey = new(MasterKey)
				}
				err = z.MasterKey.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "PrivateKey":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.PrivateKey = nil
			} else {
				if z.PrivateKey == nil {
					z.PrivateKey = new(PrivateKey)
				}
				err = z.PrivateKey.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "Signature":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Signature = nil
			} else {
				if z.Signature == nil {
					z.Signature = new(Signature)
				}
				err = z.Signature.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		case "Ciphertext":
			if dc.IsNil() {
				err = dc.ReadNil()
				if err != nil {
					return
				}
				z.Ciphertext = nil
			} else {
				if z.Ciphertext == nil {
					z.Ciphertext = new(Ciphertext)
				}
				err = z.Ciphertext.DecodeMsg(dc)
				if err != nil {
					return
				}
			}
		default:
			err = dc.Skip()
			if err != nil {
				return
			}
		}
	}
	return
}

// EncodeMsg implements msgp.Encodable
func (z *TestMessage) EncodeMsg(en *msgp.Writer) (err error) {
	// map header, size 5
	// write "Params"
	err = en.Append(0x85, 0xa6, 0x50, 0x61, 0x72, 0x61, 0x6d, 0x73)
	if err != nil {
		return err
	}
	if z.Params == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Params.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "MasterKey"
	err = en.Append(0xa9, 0x4d, 0x61, 0x73, 0x74, 0x65, 0x72, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	if z.MasterKey == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.MasterKey.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "PrivateKey"
	err = en.Append(0xaa, 0x50, 0x72, 0x69, 0x76, 0x61, 0x74, 0x65, 0x4b, 0x65, 0x79)
	if err != nil {
		return err
	}
	if z.PrivateKey == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.PrivateKey.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "Signature"
	err = en.Append(0xa9, 0x53, 0x69, 0x67, 0x6e, 0x61, 0x74, 0x75, 0x72, 0x65)
	if err != nil {
		return err
	}
	if z.Signature == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Signature.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	// write "Ciphertext"
	err = en.Append(0xaa, 0x43, 0x69, 0x70, 0x68, 0x65, 0x72, 0x74, 0x65, 0x78, 0x74)
	if err != nil {
		return err
	}
	if z.Ciphertext == nil {
		err = en.WriteNil()
		if err != nil {
			return
		}
	} else {
		err = z.Ciphertext.EncodeMsg(en)
		if err != nil {
			return
		}
	}
	return
}

// Msgsize returns an upper bound estimate of the number of bytes occupied by the serialized message
func (z *TestMessage) Msgsize() (s int) {
	s = 1 + 7
	if z.Params == nil {
		s += msgp.NilSize
	} else {
		s += z.Params.Msgsize()
	}
	s += 10
	if z.MasterKey == nil {
		s += msgp.NilSize
	} else {
		s += z.MasterKey.Msgsize()
	}
	s += 11
	if z.PrivateKey == nil {
		s += msgp.NilSize
	} else {
		s += z.PrivateKey.Msgsize()
	}
	s += 10
	if z.Signature == nil {
		s += msgp.NilSize
	} else {
		s += z.Signature.Msgsize()
	}
	s += 11
	if z.Ciphertext == nil {
		s += msgp.NilSize
	} else {
		s += z.Ciphertext.Msgsize()
	}
	return
}
