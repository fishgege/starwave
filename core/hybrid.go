package core

import (
	"io"

	"github.com/ucbrise/starwave/crypto/cryptutils"
	"github.com/ucbrise/starwave/crypto/oaque"
	"golang.org/x/crypto/nacl/secretbox"
)

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

func GenerateEncryptedSymmetricKey(random io.Reader, params *oaque.Params, precomputed *oaque.PreparedAttributeList, symm []byte) (*oaque.Ciphertext, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := oaque.EncryptPrecomputed(nil, params, precomputed, hashesToKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
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

func DecryptSymmetricKey(key *oaque.PrivateKey, encryptedKey *oaque.Ciphertext, symm []byte) []byte {
	hashesToKey := oaque.Decrypt(key, encryptedKey)
	return cryptutils.GTToSecretKey(hashesToKey, symm)
}
