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
	marshalled := make([]byte, (6+len(params.H))<<geShift)

	copy(geIndex(marshalled, 0, 2), params.G.Marshal())
	copy(geIndex(marshalled, 2, 2), params.G1.Marshal())
	copy(geIndex(marshalled, 4, 1), params.G2.Marshal())
	copy(geIndex(marshalled, 5, 2), params.G3.Marshal())
	for i, hi := range params.H {
		copy(geIndex(marshalled, 6+i, 1), hi.Marshal())
	}

	return marshalled
}

// Unmarshal recovers the parameters from an encoded byte slice.
func (params *Params) Unmarshal(marshalled []byte) (*Params, bool) {
	if len(marshalled)&((1<<geShift)-1) != 0 {
		return nil, false
	}

	params.G = new(bn256.G2)
	if _, ok := params.G.Unmarshal(geIndex(marshalled, 0, 2)); !ok {
		return nil, false
	}

	params.G1 = new(bn256.G2)
	if _, ok := params.G1.Unmarshal(geIndex(marshalled, 2, 2)); !ok {
		return nil, false
	}

	params.G2 = new(bn256.G1)
	if _, ok := params.G2.Unmarshal(geIndex(marshalled, 4, 1)); !ok {
		return nil, false
	}

	params.G3 = new(bn256.G1)
	if _, ok := params.G3.Unmarshal(geIndex(marshalled, 5, 1)); !ok {
		return nil, false
	}

	hlen := (len(marshalled) >> geShift) - 6
	params.H = make([]*bn256.G1, hlen, hlen)
	for i := range params.H {
		hi := new(bn256.G1)
		params.H[i] = hi
		if _, ok := hi.Unmarshal(geIndex(marshalled, 6+i, 1)); !ok {
			return params, false
		}
	}

	// Clear any cached values
	params.Pairing = nil

	return params, true
}

// Marshal encodes the private key as a byte slice.
func (key *PrivateKey) Marshal() []byte {
	marshalled := make([]byte, (3+len(key.B))<<geShift+len(key.B)*attributeIndexSize)

	copy(geIndex(marshalled, 0, 1), key.A0.Marshal())
	copy(geIndex(marshalled, 1, 2), key.A1.Marshal())

	for i, bi := range key.B {
		copy(geIndex(marshalled, 3+i, 1), bi.Marshal())
	}

	// To encode the free map, we need to encode the attribute index of each
	// element in B. We store the map inverted, since we know the values are
	// contiguous from 0 to len(B) - 1.
	freeMapBytes := marshalled[(3+len(key.B))<<geShift:]
	for attrIndex, bIndex := range key.FreeMap {
		freeMapBytes[bIndex] = byte(attrIndex)
	}

	return marshalled
}

// Unmarshal recovers the private key from an encoded byte slice.
func (key *PrivateKey) Unmarshal(marshalled []byte) (*PrivateKey, bool) {
	lenB := (len(marshalled) - 3*geSize) / (geSize + attributeIndexSize)
	if len(marshalled) != (3+lenB)<<geShift+lenB*attributeIndexSize {
		return nil, false
	}

	key.A0 = new(bn256.G1)
	if _, ok := key.A0.Unmarshal(geIndex(marshalled, 0, 1)); !ok {
		return nil, false
	}

	key.A1 = new(bn256.G2)
	if _, ok := key.A1.Unmarshal(geIndex(marshalled, 1, 2)); !ok {
		return nil, false
	}

	key.B = make([]*bn256.G1, lenB, lenB)
	for i := range key.B {
		bi := new(bn256.G1)
		key.B[i] = bi
		if _, ok := bi.Unmarshal(geIndex(marshalled, 3+i, 1)); !ok {
			return key, false
		}
	}

	// Rebuild the free map
	key.FreeMap = make(map[AttributeIndex]int)
	freeMapBytes := marshalled[(3+lenB)<<geShift:]
	for bIndex, attrIndex := range freeMapBytes {
		key.FreeMap[AttributeIndex(attrIndex)] = bIndex
	}

	return key, true
}

// Marshal encodes the ciphertext as a byte slice.
func (ciphertext *Ciphertext) Marshal() []byte {
	marshalled := make([]byte, 9<<geShift)

	copy(geIndex(marshalled, 0, 6), ciphertext.A.Marshal())
	copy(geIndex(marshalled, 6, 2), ciphertext.B.Marshal())
	copy(geIndex(marshalled, 8, 1), ciphertext.C.Marshal())

	return marshalled
}

// Unmarshal recovers the ciphertext from an encoded byte slice.
func (ciphertext *Ciphertext) Unmarshal(marshalled []byte) (*Ciphertext, bool) {
	if len(marshalled) != 9<<geShift {
		return nil, false
	}

	ciphertext.A = new(bn256.GT)
	if _, ok := ciphertext.A.Unmarshal(geIndex(marshalled, 0, 6)); !ok {
		return nil, false
	}
	ciphertext.B = new(bn256.G2)
	if _, ok := ciphertext.B.Unmarshal(geIndex(marshalled, 6, 2)); !ok {
		return nil, false
	}
	ciphertext.C = new(bn256.G1)
	if _, ok := ciphertext.C.Unmarshal(geIndex(marshalled, 8, 1)); !ok {
		return nil, false
	}

	return ciphertext, true
}
