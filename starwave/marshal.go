package starwave

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"reflect"

	"github.com/samkumar/embedded-pairing/lang/go/wkdibe"
	"github.com/ucbrise/starwave/core"
)

type MessageType byte

const (
	TypeInvalidMessage MessageType = iota
	TypeHierarchyDescriptor
	TypeDecryptionKey
	TypePermission
	TypeEntityDescriptor
	TypeEntitySecret
	TypeBroadeningDelegation
	TypeBroadeningDelegationWithKey
	TypeEncryptedSymmetricKey
	TypeEncryptedMessage
	TypeFullDelegation
	TypeDelegationBundle
)

func (messageType MessageType) String() string {
	switch messageType {
	case TypeHierarchyDescriptor:
		return "HierarchyDescriptor"
	case TypeDecryptionKey:
		return "DecryptionKey"
	case TypePermission:
		return "Permission"
	case TypeEntityDescriptor:
		return "EntityDescriptor"
	case TypeEntitySecret:
		return "EntitySecret"
	case TypeBroadeningDelegation:
		return "BroadeningDelegation"
	case TypeBroadeningDelegationWithKey:
		return "BroadeningDelegationWithKey"
	case TypeEncryptedSymmetricKey:
		return "EncryptedSymmetricKey"
	case TypeEncryptedMessage:
		return "EncryptedMessage"
	case TypeFullDelegation:
		return "FullDelegation"
	default:
		panic(fmt.Sprintf("Unknown message type %d", messageType))
	}
}

func (messageType MessageType) Byte() byte {
	return byte(messageType)
}

func newMessageBuffer(cap int, messageType MessageType) []byte {
	buf := make([]byte, 0, cap)
	return append(buf, messageType.Byte())
}

func checkMessageType(message []byte, expected MessageType) []byte {
	if message[0] != expected.Byte() {
		panic(fmt.Sprintf("Got %s, but expected %s", MessageType(message[0]).String(), expected.String()))
	}
	return message[1:]
}

/* Utilities for marshalling array/slice lengths. */

const MarshalledLengthLength = 4

func putLength(buf []byte, length int) []byte {
	binary.LittleEndian.PutUint32(buf, uint32(length))
	return buf
}

func getLength(buf []byte) int {
	return int(binary.LittleEndian.Uint32(buf))
}

func MarshalAppendLength(length int, buf []byte) []byte {
	lenbuf := putLength(make([]byte, MarshalledLengthLength), length)
	return append(buf, lenbuf...)
}

func UnmarshalPrefixLength(buf []byte) (int, []byte) {
	length := getLength(buf[:MarshalledLengthLength])
	buf = buf[MarshalledLengthLength:]
	return length, buf
}

/* Utilities for marshalling more complex structures. */

type Marshallable interface {
	Marshal(bool) []byte
	Unmarshal([]byte, bool, bool) bool
}

func MarshalIntoStream(m Marshallable, compressed bool) io.Reader {
	marshalled := m.Marshal(compressed)
	length := putLength(make([]byte, MarshalledLengthLength), len(marshalled))
	return io.MultiReader(bytes.NewReader(length), bytes.NewReader(marshalled))
}

func UnmarshalFromStream(m Marshallable, stream io.Reader, compressed bool, checked bool) error {
	lenbuf := make([]byte, MarshalledLengthLength)
	_, err := io.ReadFull(stream, lenbuf)
	if err != nil {
		return err
	}
	length := getLength(lenbuf)
	buf := make([]byte, length)
	_, err = io.ReadFull(stream, buf)
	if err != nil {
		return err
	}
	if !m.Unmarshal(buf, compressed, checked) {
		return errors.New("Could not unmarshal from stream")
	}
	return nil
}

func MarshalAppendWithLength(m Marshallable, buf []byte, compressed bool) []byte {
	if m == nil || reflect.ValueOf(m).IsNil() {
		return MarshalAppendLength(0, buf)
	}
	marshalled := m.Marshal(compressed)
	buf = MarshalAppendLength(len(marshalled), buf)
	buf = append(buf, marshalled...)
	return buf
}

func UnmarshalPrefixWithLengthRaw(buf []byte) ([]byte, []byte) {
	length, buf := UnmarshalPrefixLength(buf)
	if length == 0 {
		// Message was nil
		return nil, buf
	}
	return buf[:length], buf[length:]
}

func UnmarshalPrefixWithLength(m Marshallable, buf []byte, compressed bool, checked bool) ([]byte, bool) {
	rawbytes, rest := UnmarshalPrefixWithLengthRaw(buf)
	if rawbytes != nil {
		success := m.Unmarshal(rawbytes, compressed, checked)
		if !success {
			return nil, true
		}
		return rest, true
	}
	return rest, false
}

type MarshallableString struct {
	s string
}

func NewMarshallableString(str string) *MarshallableString {
	return &MarshallableString{str}
}

func NewMarshallableBytes(b []byte) *MarshallableString {
	return &MarshallableString{string(b)}
}

func (ms *MarshallableString) Marshal(compressed bool) []byte {
	return []byte(ms.s)
}

func (ms *MarshallableString) Unmarshal(buf []byte, compressed bool, checked bool) bool {
	ms.s = string(buf)
	return true
}

func (hd *HierarchyDescriptor) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(1024, TypeHierarchyDescriptor)

	buf = MarshalAppendWithLength(NewMarshallableString(hd.Nickname), buf, compressed)
	buf = MarshalAppendWithLength(hd.Params, buf, compressed)
	return buf
}

func (hd *HierarchyDescriptor) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeHierarchyDescriptor)

	ms := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&ms, buf, compressed, checked)
	if buf == nil {
		return false
	}
	hd.Nickname = ms.s

	hd.Params = new(wkdibe.Params)
	buf, _ = UnmarshalPrefixWithLength(hd.Params, buf, compressed, checked)
	if buf == nil {
		return false
	}

	return true
}

func (p *Permission) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(1024, TypePermission)

	buf = MarshalAppendWithLength(NewMarshallableBytes(core.URIToBytes(p.URI)), buf, compressed)
	buf = MarshalAppendWithLength(NewMarshallableBytes(core.TimeToBytes(p.Time)), buf, compressed)
	return buf
}

func (p *Permission) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypePermission)

	uri := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&uri, buf, compressed, checked)
	if buf == nil {
		return false
	}
	p.URI = core.URIFromBytes([]byte(uri.s))

	time := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&time, buf, compressed, checked)
	if buf == nil {
		return false
	}
	p.Time = core.TimeFromBytes([]byte(time.s))

	return true
}

func (dk *DecryptionKey) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(2048, TypeDecryptionKey)

	buf = MarshalAppendWithLength(dk.Hierarchy, buf, compressed)
	buf = MarshalAppendWithLength(dk.Key, buf, compressed)
	buf = MarshalAppendWithLength(dk.Permissions, buf, compressed)

	typeBuf := make([]byte, 4)
	binary.LittleEndian.PutUint32(typeBuf, uint32(dk.KeyType))
	buf = MarshalAppendWithLength(NewMarshallableBytes(typeBuf), buf, compressed)

	return buf
}

func (dk *DecryptionKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeDecryptionKey)

	dk.Hierarchy = new(HierarchyDescriptor)
	buf, _ = UnmarshalPrefixWithLength(dk.Hierarchy, buf, compressed, checked)
	if buf == nil {
		return false
	}

	dk.Key = new(wkdibe.SecretKey)
	buf, _ = UnmarshalPrefixWithLength(dk.Key, buf, compressed, checked)
	if buf == nil {
		return false
	}

	dk.Permissions = new(Permission)
	buf, _ = UnmarshalPrefixWithLength(dk.Permissions, buf, compressed, checked)
	if buf == nil {
		return false
	}

	typeString := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&typeString, buf, compressed, checked)
	if buf == nil {
		return false
	}
	dk.KeyType = int(binary.LittleEndian.Uint32([]byte(typeString.s)))

	return true
}

func (ed *EntityDescriptor) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(2048, TypeEntityDescriptor)

	buf = MarshalAppendWithLength(NewMarshallableString(ed.Nickname), buf, compressed)
	buf = MarshalAppendWithLength(ed.Params, buf, compressed)
	return buf
}

func (ed *EntityDescriptor) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeEntityDescriptor)

	ms := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&ms, buf, compressed, checked)
	if buf == nil {
		return false
	}
	ed.Nickname = ms.s

	ed.Params = new(wkdibe.Params)
	buf, _ = UnmarshalPrefixWithLength(ed.Params, buf, compressed, checked)
	if buf == nil {
		return false
	}

	return true
}

func (es *EntitySecret) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(2048, TypeEntitySecret)

	buf = MarshalAppendWithLength(es.Key, buf, compressed)
	buf = MarshalAppendWithLength(es.Descriptor, buf, compressed)

	return buf
}

func (es *EntitySecret) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeEntitySecret)

	es.Key = new(wkdibe.MasterKey)
	buf, _ = UnmarshalPrefixWithLength(es.Key, buf, compressed, checked)
	if buf == nil {
		return false
	}

	es.Descriptor = new(EntityDescriptor)
	buf, _ = UnmarshalPrefixWithLength(es.Descriptor, buf, compressed, checked)
	if buf == nil {
		return false
	}

	return true
}

func (esk *EncryptedSymmetricKey) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(1024, TypeEncryptedSymmetricKey)

	buf = MarshalAppendWithLength(esk.Ciphertext, buf, compressed)
	buf = MarshalAppendWithLength(esk.Signature, buf, compressed)
	buf = MarshalAppendWithLength(esk.Permissions, buf, compressed)

	return buf
}

func (esk *EncryptedSymmetricKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	var present bool
	buf := checkMessageType(marshalled, TypeEncryptedSymmetricKey)

	esk.Ciphertext = new(wkdibe.Ciphertext)
	buf, _ = UnmarshalPrefixWithLength(esk.Ciphertext, buf, compressed, checked)
	if buf == nil {
		return false
	}

	esk.Signature = new(wkdibe.Signature)
	buf, present = UnmarshalPrefixWithLength(esk.Signature, buf, compressed, checked)
	if buf == nil {
		return false
	}
	if !present {
		esk.Signature = nil
	}

	esk.Permissions = new(Permission)
	buf, _ = UnmarshalPrefixWithLength(esk.Permissions, buf, compressed, checked)
	if buf == nil {
		return false
	}

	return true
}

func (em *EncryptedMessage) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(1024+MarshalledLengthLength+len(em.Message), TypeEncryptedMessage)

	buf = MarshalAppendWithLength(em.Key, buf, compressed)
	buf = append(buf, em.IV[:]...)
	buf = MarshalAppendWithLength(NewMarshallableBytes(em.Message), buf, compressed)

	return buf
}

func (em *EncryptedMessage) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeEncryptedMessage)

	em.Key = new(EncryptedSymmetricKey)
	buf, _ = UnmarshalPrefixWithLength(em.Key, buf, compressed, checked)
	if buf == nil {
		return false
	}

	copy(em.IV[:], buf[:len(em.IV)])
	buf = buf[len(em.IV):]

	message := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&message, buf, compressed, checked)
	if buf == nil {
		return false
	}
	em.Message = []byte(message.s)

	return true
}

// UnmarshalPartial is like Unmarshal, except that it does not unmarshal the
// encrypted symmetric key. This is useful for checking if the decryption is
// already cached.
func (em *EncryptedMessage) UnmarshalPartial(marshalled []byte, compressed bool, checked bool) ([]byte, bool) {
	buf := checkMessageType(marshalled, TypeEncryptedMessage)

	ekey, buf := UnmarshalPrefixWithLengthRaw(buf)
	if buf == nil {
		return ekey, false
	}

	copy(em.IV[:], buf[:len(em.IV)])
	buf = buf[len(em.IV):]

	message := MarshallableString{}
	buf, _ = UnmarshalPrefixWithLength(&message, buf, compressed, checked)
	if buf == nil {
		return ekey, false
	}
	em.Message = []byte(message.s)

	return ekey, true
}

func (bd *BroadeningDelegation) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(2048, TypeBroadeningDelegation)

	buf = MarshalAppendWithLength(bd.Delegation, buf, compressed)
	buf = MarshalAppendWithLength(bd.From, buf, compressed)
	buf = MarshalAppendWithLength(bd.To, buf, compressed)

	return buf
}

func (bd *BroadeningDelegation) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeBroadeningDelegation)

	bd.Delegation = new(EncryptedMessage)
	buf, _ = UnmarshalPrefixWithLength(bd.Delegation, buf, compressed, checked)
	if buf == nil {
		return false
	}

	bd.From = new(EntityDescriptor)
	buf, _ = UnmarshalPrefixWithLength(bd.From, buf, compressed, checked)
	if buf == nil {
		return false
	}

	bd.To = new(EntityDescriptor)
	buf, _ = UnmarshalPrefixWithLength(bd.To, buf, compressed, checked)
	if buf == nil {
		return false
	}

	return true
}

func (bdk *BroadeningDelegationWithKey) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(2048, TypeBroadeningDelegationWithKey)

	buf = MarshalAppendWithLength(bdk.Key, buf, compressed)
	buf = MarshalAppendWithLength(bdk.To, buf, compressed)
	buf = MarshalAppendWithLength(bdk.Hierarchy, buf, compressed)

	return buf
}

func (bdk *BroadeningDelegationWithKey) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeBroadeningDelegationWithKey)

	bdk.Key = new(EncryptedMessage)
	buf, _ = UnmarshalPrefixWithLength(bdk.Key, buf, compressed, checked)
	if buf == nil {
		return false
	}

	bdk.To = new(EntityDescriptor)
	buf, _ = UnmarshalPrefixWithLength(bdk.To, buf, compressed, checked)
	if buf == nil {
		return false
	}

	bdk.Hierarchy = new(HierarchyDescriptor)
	buf, _ = UnmarshalPrefixWithLength(bdk.Hierarchy, buf, compressed, checked)
	if buf == nil {
		return false
	}

	return true
}

func (fd *FullDelegation) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(2048+(1024*len(fd.Narrow)), TypeFullDelegation)

	buf = MarshalAppendWithLength(fd.Permissions, buf, compressed)
	buf = MarshalAppendWithLength(fd.Broad, buf, compressed)
	buf = MarshalAppendLength(len(fd.Narrow), buf)
	/* In any normal FullDelegation, the "To" and "Hierarchy" fields in each
	 * BroadeningDelgationWithKey are the same. In fact, the "To" field is
	 * already in fd.Broad.
	 */
	if len(fd.Narrow) != 0 {
		buf = MarshalAppendWithLength(fd.Narrow[0].Hierarchy, buf, compressed)
	}
	for _, narrowing := range fd.Narrow {
		buf = MarshalAppendWithLength(narrowing.Key, buf, compressed)
	}

	return buf
}

func (fd *FullDelegation) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeFullDelegation)

	fd.Permissions = new(Permission)
	buf, _ = UnmarshalPrefixWithLength(fd.Permissions, buf, compressed, checked)
	fd.Broad = new(BroadeningDelegation)
	buf, _ = UnmarshalPrefixWithLength(fd.Broad, buf, compressed, checked)
	if fd.Broad.Delegation == nil {
		fd.Broad = nil
	}

	numNarrowing, buf := UnmarshalPrefixLength(buf)
	var hierarchy *HierarchyDescriptor
	if numNarrowing != 0 {
		hierarchy = new(HierarchyDescriptor)
		buf, _ = UnmarshalPrefixWithLength(hierarchy, buf, compressed, checked)
	}
	fd.Narrow = make([]*BroadeningDelegationWithKey, numNarrowing)
	for i := range fd.Narrow {
		key := new(EncryptedMessage)
		buf, _ = UnmarshalPrefixWithLength(key, buf, compressed, checked)
		if buf == nil {
			return false
		}
		fd.Narrow[i] = new(BroadeningDelegationWithKey)
		fd.Narrow[i].Key = key
		if fd.Broad != nil {
			fd.Narrow[i].To = fd.Broad.To
		}
		fd.Narrow[i].Hierarchy = hierarchy
	}

	return true
}

func (db *DelegationBundle) Marshal(compressed bool) []byte {
	buf := newMessageBuffer(4096, TypeDelegationBundle)

	buf = MarshalAppendLength(len(db.Delegations), buf)
	if len(db.Delegations) != 0 {
		// To, From, and Hierarchy are the exact same for all delegations
		var h *HierarchyDescriptor
		var to *EntityDescriptor
		var from *EntityDescriptor
		for _, deleg := range db.Delegations {
			if deleg.Broad != nil {
				if to == nil {
					to = deleg.Broad.To
				}
				if from == nil {
					from = deleg.Broad.From
				}
				if h != nil {
					break
				}
			}
			if len(deleg.Narrow) != 0 {
				if h == nil {
					h = deleg.Narrow[0].Hierarchy
				}
				if to == nil {
					to = deleg.Narrow[0].To
				}
				if to != nil && from != nil {
					break
				}
			}
		}
		buf = MarshalAppendWithLength(to, buf, compressed)
		buf = MarshalAppendWithLength(from, buf, compressed)
		buf = MarshalAppendWithLength(h, buf, compressed)
	}
	for _, delegation := range db.Delegations {
		buf = MarshalAppendWithLength(delegation.Permissions, buf, compressed)
		if delegation.Broad != nil {
			buf = MarshalAppendWithLength(delegation.Broad.Delegation, buf, compressed)
		} else {
			buf = MarshalAppendWithLength(delegation.Broad, buf, compressed)
		}
		buf = MarshalAppendLength(len(delegation.Narrow), buf)
		for _, narrowing := range delegation.Narrow {
			buf = MarshalAppendWithLength(narrowing.Key, buf, compressed)
		}
	}

	return buf
}

func (db *DelegationBundle) Unmarshal(marshalled []byte, compressed bool, checked bool) bool {
	buf := checkMessageType(marshalled, TypeDelegationBundle)

	numDelegations, buf := UnmarshalPrefixLength(buf)
	if buf == nil {
		return false
	}
	to := new(EntityDescriptor)
	from := new(EntityDescriptor)
	h := new(HierarchyDescriptor)
	if numDelegations != 0 {
		buf, _ = UnmarshalPrefixWithLength(to, buf, compressed, checked)
		if buf == nil {
			return false
		}
		buf, _ = UnmarshalPrefixWithLength(from, buf, compressed, checked)
		if buf == nil {
			return false
		}
		buf, _ = UnmarshalPrefixWithLength(h, buf, compressed, checked)
		if buf == nil {
			return false
		}
	}
	db.Delegations = make([]*FullDelegation, numDelegations)
	for i := range db.Delegations {
		db.Delegations[i] = new(FullDelegation)
		db.Delegations[i].Permissions = new(Permission)
		buf, _ = UnmarshalPrefixWithLength(db.Delegations[i].Permissions, buf, compressed, checked)
		if buf == nil {
			return false
		}
		db.Delegations[i].Broad = new(BroadeningDelegation)
		db.Delegations[i].Broad.Delegation = new(EncryptedMessage)
		db.Delegations[i].Broad.From = from
		db.Delegations[i].Broad.To = to
		buf, _ = UnmarshalPrefixWithLength(db.Delegations[i].Broad.Delegation, buf, compressed, checked)
		if buf == nil {
			return false
		}

		if db.Delegations[i].Broad.Delegation.Key == nil {
			db.Delegations[i].Broad = nil
		}

		var numNarrowing int
		numNarrowing, buf = UnmarshalPrefixLength(buf)
		if buf == nil {
			return false
		}
		db.Delegations[i].Narrow = make([]*BroadeningDelegationWithKey, numNarrowing)
		for j := range db.Delegations[i].Narrow {
			db.Delegations[i].Narrow[j] = new(BroadeningDelegationWithKey)
			db.Delegations[i].Narrow[j].Hierarchy = h
			db.Delegations[i].Narrow[j].To = to
			db.Delegations[i].Narrow[j].Key = new(EncryptedMessage)
			buf, _ = UnmarshalPrefixWithLength(db.Delegations[i].Narrow[j].Key, buf, compressed, checked)
			if buf == nil {
				return false
			}
		}
	}

	return true
}
