package lukpabe

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

func encryptHelper(t *testing.T, params *Params, attrs AttributeSet, message *bn256.GT) *Ciphertext {
	ciphertext, err := Encrypt(nil, params, attrs, message)
	if err != nil {
		t.Fatal(err)
	}
	return ciphertext
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey MasterKey, tree AccessNode) *PrivateKey {
	// Generate key for the single attributes
	key, err := KeyGen(rand.Reader, params, masterkey, tree)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decryptAndCheckHelper(t *testing.T, key *PrivateKey, ciphertext *Ciphertext, message *bn256.GT, fail bool) {
	decrypted, _ := Decrypt(key, ciphertext, nil)
	if fail {
		if decrypted != nil {
			t.Fatal("Decryption returned a message but should have failed")
		}
	} else if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func attributeFromMasterHelper(t *testing.T, attrs AttributeSet, tree AccessNode, fail bool) {
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
	key := genFromMasterHelper(t, params, masterkey, tree)

	decryptAndCheckHelper(t, key, ciphertext, message, fail)
}

func TestSingleAttribute(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13)}
	tree := &AccessLeaf{
		Attr: big.NewInt(13),
	}
	attributeFromMasterHelper(t, attrs, tree, false)
}

func TestORAccessTree(t *testing.T) {
	attrs := AttributeSet{big.NewInt(15)}
	tree := &AccessGate{
		Thresh: 1,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}
	attributeFromMasterHelper(t, attrs, tree, false)
}

func TestANDAccessTree(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13), big.NewInt(15)}
	tree := &AccessGate{
		Thresh: 2,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}
	attributeFromMasterHelper(t, attrs, tree, false)
}

func TestAccessTreeFail(t *testing.T) {
	attrs := AttributeSet{big.NewInt(13), big.NewInt(17)}
	tree := &AccessGate{
		Thresh: 2,
		Inputs: []AccessNode{&AccessLeaf{Attr: big.NewInt(13)}, &AccessLeaf{Attr: big.NewInt(15)}},
	}
	attributeFromMasterHelper(t, attrs, tree, true)
}
