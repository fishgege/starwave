package oaque

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestMarshalling(t *testing.T) {
	attrs1 := AttributeList{3: big.NewInt(108), 6: big.NewInt(88)}

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10)
	if err != nil {
		t.Fatal(err)
	}

	parambytes := params.Marshal()
	params = new(Params)
	_, ok := params.Unmarshal(parambytes)
	if !ok {
		t.Fatal("Could not unmarshal Params")
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext, err := Encrypt(nil, params, attrs1, message)
	if err != nil {
		t.Fatal(err)
	}

	ciphertextbytes := ciphertext.Marshal()
	ciphertext = new(Ciphertext)
	_, ok = ciphertext.Unmarshal(ciphertextbytes)
	if !ok {
		t.Fatal("Could not unmarshal Ciphertext")
	}

	privkey, err := KeyGenFromMaster(nil, params, key, attrs1)
	if err != nil {
		t.Fatal(err)
	}

	privkeybytes := privkey.Marshal()
	privkey = new(PrivateKey)
	_, ok = privkey.Unmarshal(privkeybytes)
	if !ok {
		t.Fatal("Could not unmarshal private key")
	}

	// Decrypt ciphertext with key and check that it is correct
	decrypted := Decrypt(privkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}