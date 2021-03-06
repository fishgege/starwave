package oaque

import (
	"bytes"
	"crypto/rand"
	"math/big"
	"testing"
)

func TestEncryptionMarshalling(t *testing.T) {
	attrs1 := AttributeList{3: big.NewInt(108), 6: big.NewInt(88)}

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10, false)
	if err != nil {
		t.Fatal(err)
	}

	parambytes := params.Marshal()
	params = new(Params)
	ok := params.Unmarshal(parambytes)
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
	ok = ciphertext.Unmarshal(ciphertextbytes)
	if !ok {
		t.Fatal("Could not unmarshal Ciphertext")
	}

	privkey, err := KeyGen(nil, params, key, attrs1)
	if err != nil {
		t.Fatal(err)
	}

	privkeybytes := privkey.Marshal()
	privkey = new(PrivateKey)
	ok = privkey.Unmarshal(privkeybytes)
	if !ok {
		t.Fatal("Could not unmarshal private key")
	}

	// Decrypt ciphertext with key and check that it is correct
	decrypted := Decrypt(privkey, ciphertext)
	if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func TestSignatureMarshalling(t *testing.T) {
	attrs1 := AttributeList{3: big.NewInt(108), 6: big.NewInt(88)}

	// Set up parameters
	params, key, err := Setup(rand.Reader, 10, true)
	if err != nil {
		t.Fatal(err)
	}

	parambytes := params.Marshal()
	params = new(Params)
	ok := params.Unmarshal(parambytes)
	if !ok {
		t.Fatal("Could not unmarshal Params")
	}

	// Come up with a message to encrypt
	message, err := RandomInZp(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}

	privkey, err := KeyGen(nil, params, key, attrs1)
	if err != nil {
		t.Fatal(err)
	}

	privkeybytes := privkey.Marshal()
	privkey = new(PrivateKey)
	ok = privkey.Unmarshal(privkeybytes)
	if !ok {
		t.Fatal("Could not unmarshal private key")
	}

	// Sign a message under the top level public key
	signature, err := Sign(nil, params, privkey, attrs1, message)
	if err != nil {
		t.Fatal(err)
	}

	signaturebytes := signature.Marshal()
	signature = new(Signature)
	ok = signature.Unmarshal(signaturebytes)
	if !ok {
		t.Fatal("Could not unmarshal Signature")
	}

	// Verify the signature
	correct := Verify(params, attrs1, signature, message)
	if !correct {
		t.Fatal("Signature was not successfully verified")
	}
}
