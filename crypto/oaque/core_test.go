package oaque

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"

	"vuvuzela.io/crypto/bn256"
)

func NewMessage() *bn256.GT {
	return bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))
}

func encryptHelper(t *testing.T, params *Params, attrs AttributeList, message *bn256.GT) *Ciphertext {
	ciphertext, err := Encrypt(nil, params, attrs, message)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey MasterKey, attrs AttributeList) *PrivateKey {
	// Generate key for the single attributes
	key, err := KeyGenFromMaster(nil, params, masterkey, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func qualifyHelper(t *testing.T, params *Params, key *PrivateKey, attrs AttributeList) *PrivateKey {
	key, err := QualifyKey(nil, params, key, attrs)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decryptAndCheckHelper(t *testing.T, key *PrivateKey, ciphertext *Ciphertext, message *bn256.GT) {
	decrypted := Decrypt(key, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func attributeFromMasterHelper(t *testing.T, attrs AttributeList) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs, message)

	// Generate key for the single attributes
	key := genFromMasterHelper(t, params, masterkey, attrs)

	decryptAndCheckHelper(t, key, ciphertext, message)
}

func TestSingleAttribute(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{0: big.NewInt(0)})
}

func TestSingleSparseAttribute(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{1: big.NewInt(0)})
}

func TestMultipleSparseAttributes(t *testing.T) {
	attributeFromMasterHelper(t, AttributeList{1: big.NewInt(0), 8: big.NewInt(123)})
}

func TestQualifyKey(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1)
	key2 := qualifyHelper(t, params, key1, attrs2)

	decryptAndCheckHelper(t, key2, ciphertext, message)
}

func TestAdditiveRandomness(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	r, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	s, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := AttributeList{2: big.NewInt(4)}
	attrs2 := AttributeList{7: big.NewInt(123)}
	attrs3 := AttributeList{2: big.NewInt(4), 7: big.NewInt(123)}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs3, message)

	// Generate key in two steps, in two different ways
	key1a, err := KeyGenFromMaster(r, params, masterkey, attrs1)
	if err != nil {
		t.Fatal(err)
	}
	key1b, err := QualifyKey(s, params, key1a, attrs3)
	if err != nil {
		t.Fatal(err)
	}

	key2a, err := KeyGenFromMaster(s, params, masterkey, attrs2)
	if err != nil {
		t.Fatal(err)
	}
	key2b, err := QualifyKey(r, params, key2a, attrs3)
	if err != nil {
		t.Fatal(err)
	}

	// Make sure both keys work...
	decryptAndCheckHelper(t, key1b, ciphertext, message)
	decryptAndCheckHelper(t, key2b, ciphertext, message)

	// Both keys should be equal to a key generated with randomness r + s
	rpluss := new(big.Int).Add(r, s)
	key3, err := KeyGenFromMaster(rpluss, params, masterkey, attrs3)
	if err != nil {
		t.Fatal(err)
	}
	decryptAndCheckHelper(t, key3, ciphertext, message)

	if !bytes.Equal(key1b.Marshal(), key3.Marshal()) {
		t.Fatal("key1b and key3 differ")
	}

	if !bytes.Equal(key2b.Marshal(), key3.Marshal()) {
		t.Fatal("key2b and key3 differ")
	}
}
