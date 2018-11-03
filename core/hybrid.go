package core

import (
	"crypto/aes"
	"crypto/cipher"
	"errors"
	"io"
	"strconv"

	"github.com/samkumar/embedded-pairing/lang/go/cryptutils"
	"github.com/samkumar/embedded-pairing/lang/go/wkdibe"
	roaque "github.com/ucbrise/starwave/crypto/roaque/csroaque/optimized"
	"golang.org/x/crypto/nacl/secretbox"
)

//******************************************************************************

func GenerateEncryptedSymmetricKeyRevoc(random io.Reader, params *roaque.Params, attrs wkdibe.AttributeList, revocList *roaque.RevocationList, symm []byte) (*roaque.Cipher, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := roaque.Encrypt(params, attrs, *revocList, hashesToKey)
	if err != nil {
		return nil, err
	}
	return ct, nil
}

//******************************************************************************

func GenerateEncryptedSymmetricKey(random io.Reader, params *wkdibe.Params, precomputed *wkdibe.PreparedAttributeList, symm []byte) (*wkdibe.Ciphertext, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct := wkdibe.EncryptPrepared(hashesToKey, params, precomputed)
	return ct, nil
}

//******************************************************************************

func DecryptSymmetricKeyRevoc(param *roaque.Params, key *roaque.PrivateKey, encryptedKey *roaque.Cipher, symm []byte) []byte {
	hashesToKey := roaque.Decrypt(param, key, encryptedKey)
	//println(hashesToKey)
	//tmpc := encryptedKey.GetCipherlist()
	//println(len(*tmpc))
	return hashesToKey.HashToSymmetricKey(symm)
}

//******************************************************************************

func DecryptSymmetricKey(key *wkdibe.SecretKey, encryptedKey *wkdibe.Ciphertext, symm []byte) []byte {
	hashesToKey := wkdibe.Decrypt(encryptedKey, key)
	return hashesToKey.HashToSymmetricKey(symm)
}

// These functions are useful for short messages (encrypted with NaCl).

// HybridEncrypt chooses a random key and encrypts with IV = 0
func HybridEncrypt(random io.Reader, params *wkdibe.Params, precomputed *wkdibe.PreparedAttributeList, message []byte) (*wkdibe.Ciphertext, []byte, error) {
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

func HybridDecrypt(encryptedKey *wkdibe.Ciphertext, encryptedMessage []byte, key *wkdibe.SecretKey, iv *[24]byte) ([]byte, bool) {
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

func HybridStreamEncryptRevoc(random io.Reader, params *roaque.Params, attrs wkdibe.AttributeList, revocList *roaque.RevocationList, input io.Reader) (*roaque.Cipher, io.Reader, error) {
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

func HybridStreamEncrypt(random io.Reader, params *wkdibe.Params, precomputed *wkdibe.PreparedAttributeList, input io.Reader) (*wkdibe.Ciphertext, io.Reader, error) {
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

func HybridStreamDecrypt(encryptedKey *wkdibe.Ciphertext, encrypted io.Reader, key *wkdibe.SecretKey) (io.Reader, error) {
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

const HybridStreamCompressed = false
const HybridStreamChecked = false

func HybridStreamDecryptConcatenatedRevoc(encrypted io.Reader, attrs wkdibe.AttributeList, param *roaque.Params, key *roaque.PrivateKey) (io.Reader, error) {
	buf := make([]byte, roaque.TotLenMarshalledSize)
	n, err := io.ReadFull(encrypted, buf[:])
	if n != len(buf) {
		return nil, err
	}

	totlen, err := strconv.ParseUint(string(buf[0:roaque.TotLenMarshalledSize]), 16, 64)
	if err != nil {
		return nil, err
	}

	marshalled := make([]byte, totlen*(uint64(wkdibe.CiphertextMarshalledLength(HybridStreamCompressed))+2*roaque.LeaveRangeMarshalledSize))
	n, err = io.ReadFull(encrypted, marshalled[:])
	if n != len(marshalled) {
		return nil, err
	}

	encryptedKey := &roaque.Cipher{}
	encryptedKey.SetAttrs(&attrs)
	//println(len(marshalled))
	if !encryptedKey.UnMarshal(append(buf, marshalled...), HybridStreamCompressed, HybridStreamChecked) {
		return nil, errors.New("Could not unmarshal ciphertext")
	}

	return HybridStreamDecryptRevoc(param, encryptedKey, encrypted, key)
}

//******************************************************************************

func HybridStreamDecryptConcatenated(encrypted io.Reader, key *wkdibe.SecretKey) (io.Reader, error) {
	marshalled := make([]byte, wkdibe.CiphertextMarshalledLength(HybridStreamCompressed))
	n, err := io.ReadFull(encrypted, marshalled)
	if n != len(marshalled) {
		return nil, err
	}

	encryptedKey := new(wkdibe.Ciphertext)
	if !encryptedKey.Unmarshal(marshalled, HybridStreamCompressed, HybridStreamChecked) {
		return nil, errors.New("Could not unmarshal ciphertext")
	}

	return HybridStreamDecrypt(encryptedKey, encrypted, key)
}
