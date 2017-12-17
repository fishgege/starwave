package core

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"

	"github.com/ucbrise/starwave/crypto/cryptutils"
	"github.com/ucbrise/starwave/crypto/oaque"
	"golang.org/x/crypto/nacl/secretbox"
)

func GenerateEncryptedSymmetricKey(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, symm []byte) (*oaque.Ciphertext, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := oaque.EncryptPrecomputed(nil, params, precomputed, hashesToKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

func DecryptSymmetricKey(key *oaque.PrivateKey, encryptedKey *oaque.Ciphertext, symm []byte) []byte {
	hashesToKey := oaque.Decrypt(key, encryptedKey)
	return cryptutils.GTToSecretKey(hashesToKey, symm)
}

// These functions are useful for short messages (encrypted with NaCl).

func HybridEncrypt(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, message []byte) (*oaque.Ciphertext, []byte, error) {
	var key [32]byte
	encryptedKey, err := GenerateEncryptedSymmetricKey(random, params, precomputed, key[:])
	if err != nil {
		return nil, nil, err
	}

	var nonce [24]byte
	buffer := make([]byte, 0, len(message)+secretbox.Overhead)
	output := secretbox.Seal(buffer, message, &nonce, &key)

	return encryptedKey, output, nil
}

func HybridDecrypt(encryptedKey *oaque.Ciphertext, encryptedMessage []byte, key *oaque.PrivateKey) ([]byte, bool) {
	var sk [32]byte
	DecryptSymmetricKey(key, encryptedKey, sk[:])

	var nonce [24]byte
	buffer := make([]byte, 0, len(encryptedMessage)-secretbox.Overhead)
	return secretbox.Open(buffer, encryptedMessage, &nonce, &sk)
}

// These functions are useful for long messages (encrypted with stream ciphers).

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
