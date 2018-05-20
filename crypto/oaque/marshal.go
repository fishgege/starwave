package oaque

import (
	"vuvuzela.io/crypto/bn256"
)

// geSize is the base size in bytes of a marshalled group element. The size of
// a marshalled element of G2 is geSize. The size of a marshalled element of G1
// is 2 * geSize. The size of a marshalled element of GT is 6 * geSize.
const geSize = 64

// geShift is the base shift for a marshalled group element
const geShift = 6

// attributeIndexSize is the size, in bytes, of an attribute index
const attributeIndexSize = 1

func geIndex(encoded []byte, index int, len int) []byte {
	return encoded[index<<geShift : (index+len)<<geShift]
}

// Marshal encodes the parameters as a byte slice.
func (params *Params) Marshal() []byte {
	var marshalled []byte
	if params.HSig == nil {
		marshalled = make([]byte, 1+(6+len(params.H))<<geShift)
		marshalled[len(marshalled)-1] = 0
	} else {
		marshalled = make([]byte, 1+(7+len(params.H))<<geShift)
		copy(geIndex(marshalled, 6+len(params.H), 1), params.HSig.Marshal())
		marshalled[len(marshalled)-1] = 1
	}

	copy(geIndex(marshalled, 0, 2), params.G.Marshal())
	copy(geIndex(marshalled, 2, 2), params.G1.Marshal())
	copy(geIndex(marshalled, 4, 1), params.G2.Marshal())
	copy(geIndex(marshalled, 5, 1), params.G3.Marshal())
	for i, hi := range params.H {
		copy(geIndex(marshalled, 6+i, 1), hi.Marshal())
	}

	return marshalled
}

// Unmarshal recovers the parameters from an encoded byte slice.
func (params *Params) Unmarshal(marshalled []byte) bool {
	if params.Pairing.Load() != nil {
		panic("Don't re-use a params object")
	}

	if len(marshalled)&((1<<geShift)-1) != 1 {
		return false
	}

	params.G = new(bn256.G2)
	if _, ok := params.G.Unmarshal(geIndex(marshalled, 0, 2)); !ok {
		return false
	}

	params.G1 = new(bn256.G2)
	if _, ok := params.G1.Unmarshal(geIndex(marshalled, 2, 2)); !ok {
		return false
	}

	params.G2 = new(bn256.G1)
	if _, ok := params.G2.Unmarshal(geIndex(marshalled, 4, 1)); !ok {
		return false
	}

	params.G3 = new(bn256.G1)
	if _, ok := params.G3.Unmarshal(geIndex(marshalled, 5, 1)); !ok {
		return false
	}

	hlen := (len(marshalled) >> geShift) - 6
	if marshalled[len(marshalled)-1] == 1 {
		hlen--
		params.HSig = new(bn256.G1)
		if _, ok := params.HSig.Unmarshal(geIndex(marshalled, 6+hlen, 1)); !ok {
			return false
		}
	}
	params.H = make([]*bn256.G1, hlen, hlen)
	for i := range params.H {
		hi := new(bn256.G1)
		params.H[i] = hi
		if _, ok := hi.Unmarshal(geIndex(marshalled, 6+i, 1)); !ok {
			return false
		}
	}

	return true
}

// Marshal encodes the master key as a byte slice.
func (key *MasterKey) Marshal() []byte {
	return (*bn256.G1)(key).Marshal()
}

// Unmarshal recovers the master key from an encoded byte slice.
func (key *MasterKey) Unmarshal(marshalled []byte) bool {
	_, success := (*bn256.G1)(key).Unmarshal(marshalled)
	return success
}

// Marshal encodes the private key as a byte slice.
func (key *PrivateKey) Marshal() []byte {
	var marshalled []byte
	var freeMapBytes []byte
	if key.BSig == nil {
		marshalled = make([]byte, (3+len(key.B))<<geShift+len(key.B)*attributeIndexSize+1)
		freeMapBytes = marshalled[(3+len(key.B))<<geShift : len(marshalled)-1]
		marshalled[len(marshalled)-1] = 0
	} else {
		marshalled = make([]byte, (4+len(key.B))<<geShift+len(key.B)*attributeIndexSize+1)
		copy(geIndex(marshalled, 3+len(key.B), 1), key.BSig.Marshal())
		freeMapBytes = marshalled[(4+len(key.B))<<geShift : len(marshalled)-1]
		marshalled[len(marshalled)-1] = 1
	}

	copy(geIndex(marshalled, 0, 1), key.A0.Marshal())
	copy(geIndex(marshalled, 1, 2), key.A1.Marshal())
	for i, bi := range key.B {
		copy(geIndex(marshalled, 3+i, 1), bi.Marshal())
	}

	// To encode the free map, we need to encode the attribute index of each
	// element in B. We store the map inverted, since we know the values are
	// contiguous from 0 to len(B) - 1.
	for attrIndex, bIndex := range key.FreeMap {
		freeMapBytes[bIndex] = byte(attrIndex)
	}

	return marshalled
}

// Unmarshal recovers the private key from an encoded byte slice.
func (key *PrivateKey) Unmarshal(marshalled []byte) bool {
	if len(marshalled) == 0 {
		return false
	}
	var lenB int
	var freeMapBytes []byte
	if marshalled[len(marshalled)-1] == 1 {
		lenB = (len(marshalled) - 4*geSize) / (geSize + attributeIndexSize)
		if len(marshalled) != (4+lenB)<<geShift+lenB*attributeIndexSize+1 {
			return false
		}
		key.BSig = new(bn256.G1)
		if _, ok := key.BSig.Unmarshal(geIndex(marshalled, 3+lenB, 1)); !ok {
			return false
		}
		freeMapBytes = marshalled[(4+lenB)<<geShift : len(marshalled)-1]
	} else {
		lenB = (len(marshalled) - 3*geSize) / (geSize + attributeIndexSize)
		if len(marshalled) != (3+lenB)<<geShift+lenB*attributeIndexSize+1 {
			return false
		}
		freeMapBytes = marshalled[(3+lenB)<<geShift : len(marshalled)-1]
	}

	key.A0 = new(bn256.G1)
	if _, ok := key.A0.Unmarshal(geIndex(marshalled, 0, 1)); !ok {
		return false
	}

	key.A1 = new(bn256.G2)
	if _, ok := key.A1.Unmarshal(geIndex(marshalled, 1, 2)); !ok {
		return false
	}

	key.B = make([]*bn256.G1, lenB, lenB)
	for i := range key.B {
		bi := new(bn256.G1)
		key.B[i] = bi
		if _, ok := bi.Unmarshal(geIndex(marshalled, 3+i, 1)); !ok {
			return false
		}
	}

	// Rebuild the free map
	key.FreeMap = make(map[AttributeIndex]int)
	for bIndex, attrIndex := range freeMapBytes {
		key.FreeMap[AttributeIndex(attrIndex)] = bIndex
	}

	return true
}

// CiphertextMarshalledSize is the size of a marshalled ciphertext, in bytes.
const CiphertextMarshalledSize = 9 << geShift

// Marshal encodes a ciphertext as a byte slice.
func (ciphertext *Ciphertext) Marshal() []byte {
	marshalled := make([]byte, CiphertextMarshalledSize)

	copy(geIndex(marshalled, 0, 6), ciphertext.A.Marshal())
	copy(geIndex(marshalled, 6, 2), ciphertext.B.Marshal())
	copy(geIndex(marshalled, 8, 1), ciphertext.C.Marshal())

	return marshalled
}

// Unmarshal recovers the ciphertext from an encoded byte slice.
func (ciphertext *Ciphertext) Unmarshal(marshalled []byte) bool {
	if len(marshalled) != CiphertextMarshalledSize {
		return false
	}

	ciphertext.A = new(bn256.GT)
	if _, ok := ciphertext.A.Unmarshal(geIndex(marshalled, 0, 6)); !ok {
		return false
	}
	ciphertext.B = new(bn256.G2)
	if _, ok := ciphertext.B.Unmarshal(geIndex(marshalled, 6, 2)); !ok {
		return false
	}
	ciphertext.C = new(bn256.G1)
	if _, ok := ciphertext.C.Unmarshal(geIndex(marshalled, 8, 1)); !ok {
		return false
	}

	return true
}

// SignatureMarshalledSize is the size of a marshalled signature, in bytes.
const SignatureMarshalledSize = 3 << geShift

// Marshal encodes a signature as a byte slice.
func (signature *Signature) Marshal() []byte {
	marshalled := make([]byte, SignatureMarshalledSize)

	copy(geIndex(marshalled, 0, 1), signature.A0.Marshal())
	copy(geIndex(marshalled, 1, 2), signature.A1.Marshal())

	return marshalled
}

// Unmarshal recovers the signature from an encoded byte slice.
func (signature *Signature) Unmarshal(marshalled []byte) bool {
	if len(marshalled) != SignatureMarshalledSize {
		return false
	}

	signature.A0 = new(bn256.G1)
	if _, ok := signature.A0.Unmarshal(geIndex(marshalled, 0, 1)); !ok {
		return false
	}

	signature.A1 = new(bn256.G2)
	if _, ok := signature.A1.Unmarshal(geIndex(marshalled, 1, 2)); !ok {
		return false
	}

	return true
}
