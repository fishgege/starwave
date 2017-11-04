package oaque

import (
	"bytes"
	"crypto/rand"
	"io"
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
	key, err := KeyGen(nil, params, masterkey, attrs)
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
	key1a, err := KeyGen(r, params, masterkey, attrs1)
	if err != nil {
		t.Fatal(err)
	}
	key1b, err := QualifyKey(s, params, key1a, attrs3)
	if err != nil {
		t.Fatal(err)
	}

	key2a, err := KeyGen(s, params, masterkey, attrs2)
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
	key3, err := KeyGen(rpluss, params, masterkey, attrs3)
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

func NewRandomMessage(random io.Reader) (*bn256.GT, error) {
	_, g1, err := bn256.RandomG1(random)
	if err != nil {
		return nil, err
	}
	_, g2, err := bn256.RandomG2(random)
	if err != nil {
		return nil, err
	}
	return bn256.Pair(g1, g2), nil
}

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := Setup(rand.Reader, 20)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func EncryptBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, _, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		b.StartTimer()
		_, err = Encrypt(nil, params, attrs, message)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkEncrypt_5(b *testing.B) {
	EncryptBenchmarkHelper(b, 5)
}

func BenchmarkEncrypt_10(b *testing.B) {
	EncryptBenchmarkHelper(b, 10)
}

func BenchmarkEncrypt_15(b *testing.B) {
	EncryptBenchmarkHelper(b, 15)
}

func BenchmarkEncrypt_20(b *testing.B) {
	EncryptBenchmarkHelper(b, 20)
}

func DecryptBenchmarkHelper(b *testing.B, numAttributes int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(nil, params, master, attrs)
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(nil, params, attrs, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		decrypted := Decrypt(key, ciphertext)
		b.StopTimer()

		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

func BenchmarkDecrypt_5(b *testing.B) {
	DecryptBenchmarkHelper(b, 5)
}

func BenchmarkDecrypt_10(b *testing.B) {
	DecryptBenchmarkHelper(b, 10)
}

func BenchmarkDecrypt_15(b *testing.B) {
	DecryptBenchmarkHelper(b, 15)
}

func BenchmarkDecrypt_20(b *testing.B) {
	DecryptBenchmarkHelper(b, 20)
}
