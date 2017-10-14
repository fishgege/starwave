package cryptutils

import (
	"crypto/sha256"
	"math/big"

	"vuvuzela.io/crypto/bn256"
)

// HashToZp hashes a byte slice to an integer in Zp*.
func HashToZp(bytestring []byte) *big.Int {
	digest := sha256.Sum256(bytestring)
	bigint := new(big.Int).SetBytes(digest[:])
	bigint.Mod(bigint, new(big.Int).Add(bn256.Order, big.NewInt(-1)))
	bigint.Add(bigint, big.NewInt(1))
	return bigint
}

// gtBase is e(g1, g2) where g1 and g2 are the base generators of G2 and G1
var gtBase *bn256.GT

// HashToGT hashes a byte slice to a group element in GT.
func HashToGT(bytestring []byte) *bn256.GT {
	if gtBase == nil {
		gtBase = bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(1)),
			new(bn256.G2).ScalarBaseMult(big.NewInt(1)))
	}
	return new(bn256.GT).ScalarMult(gtBase, HashToZp(bytestring))
}
