package core

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/ucbrise/starwave/crypto/cryptutils"
	"github.com/ucbrise/starwave/crypto/oaque"
	roaque "github.com/ucbrise/starwave/crypto/roaque/csroaque/optimized"
	"golang.org/x/crypto/nacl/secretbox"
)

//******************************************************************************

func GenerateEncryptedSymmetricKeyRevoc(random io.Reader, params *roaque.Params, attrs oaque.AttributeList, revocList *roaque.RevocationList, symm []byte) (*roaque.Cipher, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := roaque.Encrypt(params, attrs, *revocList, hashesToKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

//******************************************************************************

func GenerateEncryptedSymmetricKey(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, symm []byte) (*oaque.Ciphertext, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := oaque.EncryptPrecomputed(nil, params, precomputed, hashesToKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

//******************************************************************************

func DecryptSymmetricKeyRevoc(param *roaque.Params, key *roaque.PrivateKey, encryptedKey *roaque.Cipher, symm []byte) []byte {
	hashesToKey := roaque.Decrypt(param, key, encryptedKey)
	//println(hashesToKey)
	//tmpc := encryptedKey.GetCipherlist()
	//println(len(*tmpc))
	return cryptutils.GTToSecretKey(hashesToKey, symm)
}

//******************************************************************************

func DecryptSymmetricKey(key *oaque.PrivateKey, encryptedKey *oaque.Ciphertext, symm []byte) []byte {
	hashesToKey := oaque.Decrypt(key, encryptedKey)
	return cryptutils.GTToSecretKey(hashesToKey, symm)
}

// These functions are useful for short messages (encrypted with NaCl).

// HybridEncrypt chooses a random key and encrypts with IV = 0
func HybridEncrypt(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, message []byte) (*oaque.Ciphertext, []byte, error) {
	var key [32]byte
	encryptedKey, err := GenerateEncryptedSymmetricKey(random, params, precomputed, key[:])
	if err != nil {
		return nil, nil, err
	}

	var iv [24]byte
	output := EncryptWithSymmetricKey(random, &key, &iv, message)
	return encryptedKey, output, nil
}

func EncryptWithSymmetricKey(random io.Reader, key *[32]byte, iv *[24]byte, message []byte) []byte {
	buffer := make([]byte, 0, len(message)+secretbox.Overhead)
	output := secretbox.Seal(buffer, message, iv, key)
	return output
}

func HybridDecrypt(encryptedKey *oaque.Ciphertext, encryptedMessage []byte, key *oaque.PrivateKey, iv *[24]byte) ([]byte, bool) {
	var sk [32]byte
	DecryptSymmetricKey(key, encryptedKey, sk[:])

	return DecryptWithSymmetricKey(&sk, iv, encryptedMessage)
}

func DecryptWithSymmetricKey(key *[32]byte, iv *[24]byte, encryptedMessage []byte) ([]byte, bool) {
	buffer := make([]byte, 0, len(encryptedMessage)-secretbox.Overhead)
	return secretbox.Open(buffer, encryptedMessage, iv, key)
}

// These functions are useful for long messages (encrypted with stream ciphers).
// New secret key is chosen for every read

type HybridStreamReader struct {
	EncryptedSymmKey []byte
	SymmEncrypted    io.Reader
}

func (hsr *HybridStreamReader) Read(dst []byte) (n int, err error) {
	var copied int = 0
	if len(hsr.EncryptedSymmKey) != 0 {
		copied = copy(dst, hsr.EncryptedSymmKey)
		hsr.EncryptedSymmKey = hsr.EncryptedSymmKey[copied:]
		dst = dst[copied:]
	}

	n, err = hsr.SymmEncrypted.Read(dst)
	return copied + n, err
}

//******************************************************************************

func HybridStreamEncryptRevoc(random io.Reader, params *roaque.Params, attrs oaque.AttributeList, revocList *roaque.RevocationList, input io.Reader) (*roaque.Cipher, io.Reader, error) {
	var key [32]byte
	encryptedKey, err := GenerateEncryptedSymmetricKeyRevoc(random, params, attrs, revocList, key[:])
	if err != nil {
		return nil, nil, err
	}

	blockcipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}

	streamcipher := cipher.NewCTR(blockcipher, make([]byte, aes.BlockSize))
	symmencrypted := cipher.StreamReader{streamcipher, input}
	return encryptedKey, symmencrypted, nil
}

//******************************************************************************

func HybridStreamEncrypt(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, input io.Reader) (*oaque.Ciphertext, io.Reader, error) {
	var key [32]byte
	encryptedKey, err := GenerateEncryptedSymmetricKey(random, params, precomputed, key[:])
	if err != nil {
		return nil, nil, err
	}

	blockcipher, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, nil, err
	}

	streamcipher := cipher.NewCTR(blockcipher, make([]byte, aes.BlockSize))
	symmencrypted := cipher.StreamReader{streamcipher, input}
	return encryptedKey, symmencrypted, nil
}

//******************************************************************************

func HybridStreamDecryptRevoc(param *roaque.Params, encryptedKey *roaque.Cipher, encrypted io.Reader, key *roaque.PrivateKey) (io.Reader, error) {
	var sk [32]byte

	//tmpc := encryptedKey.GetCipherlist()

	DecryptSymmetricKeyRevoc(param, key, encryptedKey, sk[:])

	blockcipher, err := aes.NewCipher(sk[:])
	if err != nil {
		return nil, err
	}

	streamcipher := cipher.NewCTR(blockcipher, make([]byte, aes.BlockSize))
	symmdecrypted := cipher.StreamReader{streamcipher, encrypted}
	return symmdecrypted, nil
}

//******************************************************************************

func HybridStreamDecrypt(encryptedKey *oaque.Ciphertext, encrypted io.Reader, key *oaque.PrivateKey) (io.Reader, error) {
	var sk [32]byte
	DecryptSymmetricKey(key, encryptedKey, sk[:])

	blockcipher, err := aes.NewCipher(sk[:])
	if err != nil {
		return nil, err
	}

	streamcipher := cipher.NewCTR(blockcipher, make([]byte, aes.BlockSize))
	symmdecrypted := cipher.StreamReader{streamcipher, encrypted}
	return symmdecrypted, nil
}

//******************************************************************************

func HybridStreamDecryptConcatenatedRevoc(encrypted io.Reader, attrs oaque.AttributeList, param *roaque.Params, key *roaque.PrivateKey) (io.Reader, error) {
	marshalled := make([]byte, 0)

	//NOTE:io read can be improved.
	buf := make([]byte, 1)
	for true {
		n, err := io.ReadFull(encrypted, buf)
		if n != 1 {
			return nil, err
		}

		marshalled = append(marshalled, buf[0])
		if buf[0] == '&' {
			break
		}
	}

	encryptedKey := &roaque.Cipher{}
	encryptedKey.SetAttrs(&attrs)
	println(len(marshalled))
	if !encryptedKey.UnMarshal(marshalled) {
		return nil, errors.New("Could not unmarshal ciphertext")
	}

	return HybridStreamDecryptRevoc(param, encryptedKey, encrypted, key)
}

//******************************************************************************

func HybridStreamDecryptConcatenated(encrypted io.Reader, key *oaque.PrivateKey) (io.Reader, error) {
	var marshalled [oaque.CiphertextMarshalledSize]byte
	n, err := io.ReadFull(encrypted, marshalled[:])
	if n != len(marshalled) {
		return nil, err
	}

	encryptedKey := new(oaque.Ciphertext)
	if !encryptedKey.Unmarshal(marshalled[:]) {
		return nil, errors.New("Could not unmarshal ciphertext")
	}

	return HybridStreamDecrypt(encryptedKey, encrypted, key)
}
