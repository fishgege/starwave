// Package lukpabe implements Large-Universe Key-Policy Attribute-Based
// Encryption. The construction is described in Section 5 of the paper
// "Attribute-Based Encryption for Fined-Grained Access Control of Encrypted
// Data" by Goyal, Pandey, Sahai, and Waters.
package lukpabe

import (
	"crypto/rand"
	"io"
	"math/big"

	"vuvuzela.io/crypto/bn256"
)

// Params represents the system parameters for an LU KP-ABE cryptosystem.
type Params struct {
	G1 *bn256.G2
	G2 *bn256.G1
	Ts []*bn256.G1

	// Some cached state
	Pairing      *bn256.GT
	InverseTable []*big.Int
}

// MasterKey represents the key that can generate a private key for any access
// tree.
type MasterKey *big.Int

// AttributeSet represents a set of attributes. Each attribute is an integer in
// Zp*.
type AttributeSet []*big.Int

// AccessNode represents a node of an access tree.
type AccessNode interface {
	IsLeaf() bool
	Threshold() int
	Children() []AccessNode
	Attribute() *big.Int
}

// AccessGate represents an internal node of an access tree.
type AccessGate struct {
	Thresh int
	Inputs []AccessNode
}

func (ag *AccessGate) IsLeaf() bool {
	return false
}

func (ag *AccessGate) Threshold() int {
	return ag.Thresh
}

func (ag *AccessGate) Children() []AccessNode {
	return ag.Inputs
}

func (ag *AccessGate) Attribute() *big.Int {
	panic("Not a leaf node")
}

// AccessLeaf represents a leaf node of an access tree.
type AccessLeaf big.Int

func (al *AccessLeaf) IsLeaf() bool {
	return true
}

func (al *AccessLeaf) Threshold() int {
	return 1
}

func (al *AccessLeaf) Children() []AccessNode {
	panic("Not an internal node")
}

func (al *AccessLeaf) Attribute() *big.Int {
	return (*big.Int)(al)
}

// PrivateKey represents a private key for an access tree.
type PrivateKey struct {
	D []*bn256.G1
	R []*bn256.G2
}

// Ciphertext represents an encrypted message.
type Ciphertext struct {
	E1    *bn256.GT
	E2    *bn256.G2
	Es    []*bn256.G1
	Gamma AttributeSet
}

// RandomInZp returns an element chosen from Zp uniformly at random, using the
// provided reader as a random number source.
func RandomInZp(random io.Reader) (*big.Int, error) {
	return rand.Int(random, bn256.Order)
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "n" is the maximum number of attributes under
// which a message may be encrypted.
func Setup(random io.Reader, n int) (*Params, MasterKey, error) {
	params := new(Params)

	var err error
	var y *big.Int
	y, params.G1, err = bn256.RandomG2(random)
	if err != nil {
		return nil, nil, err
	}

	_, params.G2, err = bn256.RandomG1(random)
	if err != nil {
		return nil, nil, err
	}

	params.Ts = make([]*bn256.G1, n+1)
	for i := range params.Ts {
		_, params.Ts[i], err = bn256.RandomG1(random)
		if err != nil {
			return nil, nil, err
		}
	}

	return params, y, nil
}

// Precache forces "cached params" to be computed. Normally, they are computed
// on the fly, but that is not thread-safe. If you plan to call functions
// (especially Encrypt) multiple times concurrently, you should call this first,
// to eliminate race conditions.
func (params *Params) Precache() {
	if params.Pairing == nil {
		params.Pairing = bn256.Pair(params.G2, params.G1)
	}
	if params.InverseTable == nil {
		params.InverseTable = make([]*big.Int, 2*len(params.Ts)-1)
		n := len(params.Ts) - 1
		for k := range params.InverseTable {
			iMinusJ := big.NewInt(int64(k - n))
			params.InverseTable[k] = iMinusJ.ModInverse(iMinusJ, bn256.Order)
		}
	}
}

// KeyGen generates a private key for the specified access tree, using the
// master key.
func KeyGen(random io.Reader, params *Params, master MasterKey, tree AccessNode) error {
	return nil
}

// T implements the function T for a cryptosystem, as described in the paper.
// According to the paper, if we are willing to accept random oracles, then we
// can replace this with a hash function.
func (params *Params) T(x *big.Int) *bn256.G1 {
	n := len(params.Ts) - 1

	// Compute g2 ^ (X^n)
	exp := new(big.Int).Exp(x, big.NewInt(int64(n)), bn256.Order)
	ret := new(bn256.G1).ScalarMult(params.G2, exp)

	for i, t := range params.Ts {
		// Compute Lagrange Coefficient for i, {1, ..., n + 1}
		lagrange := big.NewInt(1)
		for j := range params.Ts {
			if j != i {
				jInt := big.NewInt(int64(j))
				lagrange.Mul(lagrange, jInt.Sub(x, jInt))
				lagrange.Mul(lagrange, params.InverseTable[i-j+n])
				lagrange.Mod(lagrange, bn256.Order)
			}
		}

		ret.Add(ret, new(bn256.G1).ScalarMult(t, lagrange))
	}

	return ret
}

func Encrypt(s *big.Int, params *Params, attrs AttributeSet, message *bn256.GT) (*Ciphertext, error) {
	ciphertext := new(Ciphertext)

	if s == nil {
		var err error
		s, err = RandomInZp(rand.Reader)
		if err != nil {
			return nil, err
		}
	}

	params.Precache()

	ciphertext.E1 = new(bn256.GT).ScalarMult(params.Pairing, s)
	ciphertext.E1.Add(message, ciphertext.E1)

	ciphertext.E2 = new(bn256.G2).ScalarBaseMult(s)

	ciphertext.Es = make([]*bn256.G1, len(attrs))
	for index, i := range attrs {
		ti := params.T(i)
		ciphertext.Es[index] = ti.ScalarMult(ti, s)
	}

	ciphertext.Gamma = attrs

	return ciphertext, nil
}
