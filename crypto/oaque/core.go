// Package oaque implements OAQUE, which is Ordered-Attribute-Qualified
// Encryption. The construction is based on the HIBE construction.
package oaque

import (
	"crypto/rand"
	"io"
	"math/big"

	"vuvuzela.io/crypto/bn256"
)

// Params represents the system parameters for an OAQUE cryptosystem.
type Params struct {
	G  *bn256.G2
	G1 *bn256.G2
	G2 *bn256.G1
	G3 *bn256.G1
	H  []*bn256.G1

	// Some cached state
	Pairing *bn256.GT
}

// AttributeIndex represents an attribute --- specifically, its index in the
// array of attributes.
type AttributeIndex uint8

// AttributeList represents a list of attributes. It is map from each set
// attribute (by its index) to the value of that attribute.
type AttributeList map[AttributeIndex]*big.Int

// MasterKey represents the key for a hierarchy that can create a key for any
// element.
type MasterKey *bn256.G1

// MaximumDepth returns the number of attributes supported. This was specified
// via the "l" argument when Setup was called.
func (params *Params) NumAttributes() int {
	return len(params.H)
}

// PrivateKey represents a key for an ID in a hierarchy that can decrypt
// messages encrypted with that ID and issue keys for children of that ID in
// the hierarchy.
type PrivateKey struct {
	A0      *bn256.G1
	A1      *bn256.G2
	B       []*bn256.G1
	FreeMap map[AttributeIndex]int
}

// Ciphertext represents an encrypted message.
type Ciphertext struct {
	A *bn256.GT
	B *bn256.G2
	C *bn256.G1
}

// FreeAttributes returns the indexes of unbound attributes.
func (privkey *PrivateKey) FreeAttributes() []AttributeIndex {
	free := make([]AttributeIndex, len(privkey.FreeMap))
	for idx := range privkey.FreeMap {
		free = append(free, idx)
	}
	return free
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 1 to l-1).
func Setup(random io.Reader, l int) (*Params, MasterKey, error) {
	params := &Params{}
	var err error

	// The algorithm technically needs g to be a generator of G, but since G is
	// isomorphic to Zp, any element in G is technically a generator. So, we
	// just choose a random element.
	_, params.G, err = bn256.RandomG2(random)
	if err != nil {
		return nil, nil, err
	}

	// Choose a random alpha in Zp.
	alpha, err := rand.Int(random, bn256.Order)
	if err != nil {
		return nil, nil, err
	}

	// Choose g1 = g ^ alpha.
	params.G1 = new(bn256.G2).ScalarMult(params.G, alpha)

	// Randomly choose g2 and g3.
	_, params.G2, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}
	_, params.G3, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}

	// Randomly choose h1 ... hl.
	params.H = make([]*bn256.G1, l, l)
	for i := range params.H {
		_, params.H[i], err = bn256.RandomG1(random)
		if err != nil {
			return nil, nil, err
		}
	}

	// Compute the master key as g2 ^ alpha.
	master := new(bn256.G1).ScalarMult(params.G2, alpha)

	return params, master, nil
}

// RandomInZp returns an element chosen from Zp uniformly at random, using the
// provided reader as a random number source.
func RandomInZp(random io.Reader) (*big.Int, error) {
	return rand.Int(random, bn256.Order)
}

// KeyGenFromMaster generates a key for an attribute list using the master key.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. The parameter "r" is an element of Zp. It should
// be chosen uniformly at random, and represents the randomness to use to
// generate the key. If left as nil, it will be generated using a cryptographic
// random number generator.
func KeyGenFromMaster(r *big.Int, params *Params, master MasterKey, attrs AttributeList) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(attrs)
	l := len(params.H)

	// Randomly choose r in Zp.
	if r == nil {
		var err error
		r, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	product := new(bn256.G1).Set(params.G3)
	key.B = make([]*bn256.G1, l-k)
	key.FreeMap = make(map[AttributeIndex]int)
	j := 0
	for i, h := range params.H {
		attrIndex := AttributeIndex(i)
		if attr, ok := attrs[attrIndex]; ok {
			hi := new(bn256.G1).ScalarMult(h, attr)
			product.Add(product, hi)
		} else {
			key.B[j] = new(bn256.G1).ScalarMult(h, r)
			key.FreeMap[attrIndex] = j
			j++
		}
	}
	product.ScalarMult(product, r)

	key.A0 = new(bn256.G1).Add(master, product)
	key.A1 = new(bn256.G2).ScalarMult(params.G, r)

	return key, nil
}

// QualifyKey uses a key to generate a new key with restricted permissions, by
// adding the the specified attributes. Remember that adding new attributes
// restricts the permissions. Furthermore, attributes are immutable once set,
// so the attrs map must contain mappings for attributes that are already set.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. The parameter "t" is an element of Zp. It should
// be chosen uniformly at random, and represents the randomness to use to
// generate the new key. If left as nil, it will be generated using Go's
// crypto/rand.
func QualifyKey(t *big.Int, params *Params, qualify *PrivateKey, attrs AttributeList) (*PrivateKey, error) {
	key := &PrivateKey{}
	k := len(attrs)
	l := len(params.H)

	// Randomly choose t in Zp
	if t == nil {
		var err error
		t, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	key.A0 = new(bn256.G1).Set(qualify.A0)
	product := new(bn256.G1).Set(params.G3)
	key.B = make([]*bn256.G1, l-k)
	key.FreeMap = make(map[AttributeIndex]int)
	j := 0
	for i, h := range params.H {
		attrIndex := AttributeIndex(i)
		if attr, ok := attrs[attrIndex]; ok {
			hi := new(bn256.G1).ScalarMult(h, attr)
			product.Add(product, hi)
			if index, ok := qualify.FreeMap[attrIndex]; ok {
				bi := new(bn256.G1).ScalarMult(qualify.B[index], attr)
				key.A0.Add(key.A0, bi)
			}
		} else {
			key.B[j] = new(bn256.G1).ScalarMult(h, t)
			bidx, ok := qualify.FreeMap[AttributeIndex(i)]
			if !ok {
				panic("Attributes are not a superset of those of provided key")
			}
			key.B[j].Add(qualify.B[bidx], key.B[j])
			key.FreeMap[attrIndex] = j
			j++
		}
	}
	product.ScalarMult(product, t)

	key.A0.Add(key.A0, product)

	key.A1 = new(bn256.G2).ScalarMult(params.G, t)
	key.A1.Add(qualify.A1, key.A1)

	return key, nil
}

// Precache forces "cached params" to be computed. Normally, they are computed
// on the fly, but that is not thread-safe. If you plan to call functions
// (especially Encrypt) multiple times concurrently, you should call this first,
// to eliminate race conditions.
func (params *Params) Precache() {
	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}
}

// Encrypt converts the provided message to ciphertext, using the provided ID
// as the public key. The argument "s" is the randomness to use, and should be
// an integer chosen uniformly at random from Zp.
func Encrypt(s *big.Int, params *Params, attrs AttributeList, message *bn256.GT) (*Ciphertext, error) {
	ciphertext := &Ciphertext{}

	// Randomly choose s in Zp
	if s == nil {
		var err error
		s, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}

	ciphertext.A = new(bn256.GT)
	ciphertext.A.ScalarMult(params.Pairing, s)
	ciphertext.A.Add(ciphertext.A, message)

	ciphertext.B = new(bn256.G2).ScalarMult(params.G, s)

	ciphertext.C = new(bn256.G1).Set(params.G3)
	for attrIndex, attr := range attrs {
		h := new(bn256.G1).ScalarMult(params.H[attrIndex], attr)
		ciphertext.C.Add(ciphertext.C, h)
	}
	ciphertext.C.ScalarMult(ciphertext.C, s)

	return ciphertext, nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(key *PrivateKey, ciphertext *Ciphertext) *bn256.GT {
	plaintext := bn256.Pair(ciphertext.C, key.A1)
	invdenominator := new(bn256.GT).Neg(bn256.Pair(key.A0, ciphertext.B))
	plaintext.Add(plaintext, invdenominator)
	plaintext.Add(ciphertext.A, plaintext)
	return plaintext
}
