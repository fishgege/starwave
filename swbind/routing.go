package swbind

import (
	"crypto/sha256"
	"encoding/binary"

	"github.com/immesys/bw2/objects"
)

// This is a replacement of some of the functionality in "routing.go" in
// the standard bw2 objects package. The only change here is to allow contact
// and comment fields that are greater than 255 bytes long.

const DOTROStart = 66
const EntityROStart = 32
const EntityWithKeyROStart = 64

func appendChunkedString(buf []byte, header byte, str []byte) []byte {
	if len(str) == 0 {
		return buf
	}
	done := false
	for i := 0; !done; i += 255 {
		var chunk []byte
		if i+255 >= len(str) {
			chunk = str[i:]
			done = true
		} else {
			chunk = str[i : i+255]
		}

		buf = append(buf, header, byte(len(chunk)))
		buf = append(buf, chunk...)
	}
	return buf
}

func GetField(ro []byte, header byte, startidx int) []byte {
	field := make([]byte, 0, 2048)

	index := startidx
	for ro[index] != 0 {
		length := int(ro[index+1])
		if ro[index] == header {
			field = append(field, ro[index+2:index+2+length]...)
		}
		index += (2 + length)
	}

	return field
}

func GetContactInEntity(ent []byte) []byte {
	return GetField(ent, 0x05, EntityROStart)
}

func GetCommentInEntity(ent []byte) []byte {
	return GetField(ent, 0x06, EntityROStart)
}

func GetContactInDOT(dot []byte) []byte {
	return GetField(dot, 0x05, DOTROStart)
}

func GetCommentInDOT(dot []byte) []byte {
	return GetField(dot, 0x06, DOTROStart)
}

func FindHeader(ro []byte, header byte, startidx int) int {
	index := startidx
	for ro[index] != 0 {
		length := int(ro[index+1])
		index += (2 + length)
	}
	return index
}

func AddContactAndCommentToRO(ro []byte, startidx int, contact []byte, comment []byte, sk []byte) []byte {
	zeroidx := FindHeader(ro, 0x00, startidx)
	roprefix := ro[:zeroidx]
	rosuffix := make([]byte, len(ro)-zeroidx)
	copy(rosuffix, ro[zeroidx:])

	roprefix = appendChunkedString(roprefix, 0x05, contact)
	roprefix = appendChunkedString(roprefix, 0x06, comment)
	ro = append(roprefix, rosuffix...)

	// We changed the DOT, so we need to recompute the signature
	objects.SignBlob(sk, ro[0:32], ro[len(ro)-64:], ro[:len(ro)-64])
	return ro
}

func GetDOTHash(dot []byte) []byte {
	digest := sha256.Sum256(dot[:len(dot)-64])
	return digest[:]
}

func AddContactAndCommentToDOT(dot []byte, contact []byte, comment []byte, sk []byte) []byte {
	return AddContactAndCommentToRO(dot, DOTROStart, contact, comment, sk)
}

func AddContactAndCommentToEntity(ent []byte, contact []byte, comment []byte, sk []byte) []byte {
	return AddContactAndCommentToRO(ent, EntityROStart, contact, comment, sk)
}

func AddContactAndCommentToEntityWithKey(ent []byte, contact []byte, comment []byte) []byte {
	newent := AddContactAndCommentToEntity(ent[32:], contact, comment, ent[:32])
	newentwithkey := make([]byte, 32+len(newent))
	copy(newentwithkey[0:32], ent[0:32])
	copy(newentwithkey[32:], newent)
	return newentwithkey
}

func EndOfDOT(dot []byte) int {
	index := FindHeader(dot, 0x00, DOTROStart)

	// Skip one-byte "zero" at end of RO header
	index += 1

	// Skip two-byte permission encoding
	index += 2

	// Skip 32-byte MVK
	index += 32

	//fmt.Println(blob[index:])

	// Skip URI
	length := binary.LittleEndian.Uint16(dot[index : index+2])
	index += (2 + int(length))

	// Skip 64-byte signature
	index += 64

	return index
}

func EndOfEntity(ent []byte) int {
	index := FindHeader(ent, 0x00, EntityROStart)

	// Skip one-byte "zero" at end of RO header
	index += 1

	// Skip 64-byte signature
	index += 64

	return index
}

func EndOfEntityWithKey(ent []byte) int {
	return 32 + EndOfEntity(ent[32:])
}
