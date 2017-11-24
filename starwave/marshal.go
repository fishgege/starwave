package starwave

import (
	"encoding/binary"
	"fmt"

	"github.com/SoftwareDefinedBuildings/starwave/core"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
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

func putLength(buf []byte, length int) {
	binary.LittleEndian.PutUint32(buf, uint32(length))
}

func getLength(buf []byte) int {
	return int(binary.LittleEndian.Uint32(buf))
}

func MarshalAppendLength(length int, buf []byte) []byte {
	lenbuf := make([]byte, MarshalledLengthLength)
	putLength(lenbuf, length)
	return append(buf, lenbuf...)
}

func UnmarshalPrefixLength(buf []byte) (int, []byte) {
	length := getLength(buf[:MarshalledLengthLength])
	buf = buf[MarshalledLengthLength:]
	return length, buf
}

/* Utilities for marshalling more complex structures. */

type Marshallable interface {
	Marshal() []byte
	Unmarshal([]byte) bool
}

func MarshalAppendWithLength(m Marshallable, buf []byte) []byte {
	marshalled := m.Marshal()
	buf = MarshalAppendLength(len(marshalled), buf)
	buf = append(buf, marshalled...)
	return buf
}

func UnmarshalPrefixWithLength(m Marshallable, buf []byte) []byte {
	length, buf := UnmarshalPrefixLength(buf)
	success := m.Unmarshal(buf[:length])
	if !success {
		return nil
	}
	return buf[length:]
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

func (ms *MarshallableString) Marshal() []byte {
	return []byte(ms.s)
}

func (ms *MarshallableString) Unmarshal(buf []byte) bool {
	ms.s = string(buf)
	return true
}

func (hd *HierarchyDescriptor) Marshal() []byte {
	buf := newMessageBuffer(1024, TypeHierarchyDescriptor)

	buf = MarshalAppendWithLength(NewMarshallableString(hd.Nickname), buf)
	buf = MarshalAppendWithLength(hd.Params, buf)
	return buf
}

func (hd *HierarchyDescriptor) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeHierarchyDescriptor)

	ms := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&ms, buf)
	if buf == nil {
		return false
	}
	hd.Nickname = ms.s

	hd.Params = new(oaque.Params)
	buf = UnmarshalPrefixWithLength(hd.Params, buf)
	if buf == nil {
		return false
	}

	return true
}

func (p *Permission) Marshal() []byte {
	buf := newMessageBuffer(1024, TypePermission)

	buf = MarshalAppendWithLength(NewMarshallableBytes(core.URIToBytes(p.URI)), buf)
	buf = MarshalAppendWithLength(NewMarshallableBytes(core.TimeToBytes(p.Time)), buf)
	return buf
}

func (p *Permission) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypePermission)

	uri := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&uri, buf)
	if buf == nil {
		return false
	}
	p.URI = core.URIFromBytes([]byte(uri.s))

	time := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&time, buf)
	if buf == nil {
		return false
	}
	p.Time = core.TimeFromBytes([]byte(time.s))

	return true
}

func (dk *DecryptionKey) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeDecryptionKey)

	buf = MarshalAppendWithLength(dk.Hierarchy, buf)
	buf = MarshalAppendWithLength(dk.Key, buf)
	buf = MarshalAppendWithLength(dk.Permissions, buf)

	return buf
}

func (dk *DecryptionKey) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeDecryptionKey)

	dk.Hierarchy = new(HierarchyDescriptor)
	buf = UnmarshalPrefixWithLength(dk.Hierarchy, buf)
	if buf == nil {
		return false
	}

	dk.Key = new(oaque.PrivateKey)
	buf = UnmarshalPrefixWithLength(dk.Key, buf)
	if buf == nil {
		return false
	}

	dk.Permissions = new(Permission)
	buf = UnmarshalPrefixWithLength(dk.Permissions, buf)
	if buf == nil {
		return false
	}

	return true
}

func (ed *EntityDescriptor) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeEntityDescriptor)

	buf = MarshalAppendWithLength(NewMarshallableString(ed.Nickname), buf)
	buf = MarshalAppendWithLength(ed.Params, buf)
	return buf
}

func (ed *EntityDescriptor) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEntityDescriptor)

	ms := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&ms, buf)
	if buf == nil {
		return false
	}
	ed.Nickname = ms.s

	ed.Params = new(oaque.Params)
	buf = UnmarshalPrefixWithLength(ed.Params, buf)
	if buf == nil {
		return false
	}

	return true
}

func (es *EntitySecret) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeEntitySecret)

	buf = MarshalAppendWithLength(es.Key, buf)
	buf = MarshalAppendWithLength(es.Descriptor, buf)

	return buf
}

func (es *EntitySecret) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEntitySecret)

	es.Key = new(oaque.MasterKey)
	buf = UnmarshalPrefixWithLength(es.Key, buf)
	if buf == nil {
		return false
	}

	es.Descriptor = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(es.Descriptor, buf)
	if buf == nil {
		return false
	}

	return true
}

func (esk *EncryptedSymmetricKey) Marshal() []byte {
	buf := newMessageBuffer(1024, TypeEncryptedSymmetricKey)

	buf = MarshalAppendWithLength(esk.Ciphertext, buf)
	buf = MarshalAppendWithLength(esk.Permissions, buf)

	return buf
}

func (esk *EncryptedSymmetricKey) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEncryptedSymmetricKey)

	esk.Ciphertext = new(oaque.Ciphertext)
	buf = UnmarshalPrefixWithLength(esk.Ciphertext, buf)
	if buf == nil {
		return false
	}

	esk.Permissions = new(Permission)
	buf = UnmarshalPrefixWithLength(esk.Permissions, buf)
	if buf == nil {
		return false
	}

	return true
}

func (em *EncryptedMessage) Marshal() []byte {
	buf := newMessageBuffer(1024+MarshalledLengthLength+len(em.Message), TypeEncryptedMessage)

	buf = MarshalAppendWithLength(em.Key, buf)
	buf = MarshalAppendWithLength(NewMarshallableBytes(em.Message), buf)

	return buf
}

func (em *EncryptedMessage) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeEncryptedMessage)

	em.Key = new(EncryptedSymmetricKey)
	buf = UnmarshalPrefixWithLength(em.Key, buf)
	if buf == nil {
		return false
	}

	message := MarshallableString{}
	buf = UnmarshalPrefixWithLength(&message, buf)
	if buf == nil {
		return false
	}
	em.Message = []byte(message.s)

	return true
}

func (bd *BroadeningDelegation) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeBroadeningDelegation)

	buf = MarshalAppendWithLength(bd.Delegation, buf)
	buf = MarshalAppendWithLength(bd.From, buf)
	buf = MarshalAppendWithLength(bd.To, buf)

	return buf
}

func (bd *BroadeningDelegation) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeBroadeningDelegation)

	bd.Delegation = new(EncryptedMessage)
	buf = UnmarshalPrefixWithLength(bd.Delegation, buf)
	if buf == nil {
		return false
	}

	bd.From = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(bd.From, buf)
	if buf == nil {
		return false
	}

	bd.To = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(bd.To, buf)
	if buf == nil {
		return false
	}

	return true
}

func (bdk *BroadeningDelegationWithKey) Marshal() []byte {
	buf := newMessageBuffer(2048, TypeBroadeningDelegationWithKey)

	buf = MarshalAppendWithLength(bdk.Key, buf)
	buf = MarshalAppendWithLength(bdk.To, buf)
	buf = MarshalAppendWithLength(bdk.Hierarchy, buf)

	return buf
}

func (bdk *BroadeningDelegationWithKey) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeBroadeningDelegationWithKey)

	bdk.Key = new(EncryptedMessage)
	buf = UnmarshalPrefixWithLength(bdk.Key, buf)
	if buf == nil {
		return false
	}

	bdk.To = new(EntityDescriptor)
	buf = UnmarshalPrefixWithLength(bdk.To, buf)
	if buf == nil {
		return false
	}

	bdk.Hierarchy = new(HierarchyDescriptor)
	buf = UnmarshalPrefixWithLength(bdk.Hierarchy, buf)
	if buf == nil {
		return false
	}

	return true
}

func (fd *FullDelegation) Marshal() []byte {
	buf := newMessageBuffer(2048+(1024*len(fd.Narrow)), TypeFullDelegation)

	buf = MarshalAppendWithLength(fd.Broad, buf)
	buf = MarshalAppendLength(len(fd.Narrow), buf)
	for _, narrowing := range fd.Narrow {
		buf = MarshalAppendWithLength(narrowing, buf)
	}

	return buf
}

func (fd *FullDelegation) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeFullDelegation)

	fd.Broad = new(BroadeningDelegation)
	buf = UnmarshalPrefixWithLength(fd.Broad, buf)

	numNarrowing, buf := UnmarshalPrefixLength(buf)

	fd.Narrow = make([]*BroadeningDelegationWithKey, numNarrowing)
	for i := range fd.Narrow {
		fd.Narrow[i] = new(BroadeningDelegationWithKey)
		buf = UnmarshalPrefixWithLength(fd.Narrow[i], buf)
		if buf == nil {
			return false
		}
	}

	return true
}

func (db *DelegationBundle) Marshal() []byte {
	buf := newMessageBuffer(4096, TypeDelegationBundle)

	buf = MarshalAppendLength(len(db.Delegations), buf)
	for _, delegation := range db.Delegations {
		buf = MarshalAppendWithLength(delegation, buf)
	}

	return buf
}

func (db *DelegationBundle) Unmarshal(marshalled []byte) bool {
	buf := checkMessageType(marshalled, TypeDelegationBundle)

	numDelegations, buf := UnmarshalPrefixLength(buf)
	db.Delegations = make([]*FullDelegation, numDelegations)
	for i := range db.Delegations {
		db.Delegations[i] = new(FullDelegation)
		buf = UnmarshalPrefixWithLength(db.Delegations[i], buf)
		if buf == nil {
			return false
		}
	}

	return true
}
