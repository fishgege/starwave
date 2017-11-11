package starwave

import (
	"crypto/rand"
	"io"
	"math/big"

	"github.com/SoftwareDefinedBuildings/starwave/core"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
	"golang.org/x/crypto/nacl/secretbox"
)

type HierarchyDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

type DecryptionKey struct {
	Hierarchy   *HierarchyDescriptor
	Key         *oaque.PrivateKey
	Permissions *Permission
}

type Permission struct {
	URI  core.URIPath
	Time core.TimePath
}

func (p *Permission) AttributeSet() oaque.AttributeList {
	return core.AttributeSetFromPaths(p.URI, p.Time)
}

type EntityDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

type EntitySecret struct {
	Key oaque.MasterKey
}

type BroadeningDelegation struct {
	EncryptedMessage
}

type BroadeningDelegationWithKey struct {
	EncryptedMessage
}

type EncryptedSymmetricKey struct {
	Ciphertext  *oaque.Ciphertext
	Permissions *Permission
}

type EncryptedMessage struct {
	Key     *EncryptedSymmetricKey
	Message []byte
}

type Encryptor struct {
	Hierarchy   *HierarchyDescriptor
	Permissions *Permission
	Precomputed *oaque.PartialEncryption
}

type Decryptor oaque.PrivateKey

const (
	MaxURIDepth = core.MaxURILength
	TimeDepth   = core.MaxTimeLength
)

func CreateHierarchy(random io.Reader, uriDepth int, nickname string) (*HierarchyDescriptor, *DecryptionKey, error) {
	numSlots := uriDepth + TimeDepth

	params, masterKey, err := oaque.Setup(rand.Reader, numSlots)
	if err != nil {
		return nil, nil, err
	}

	randomInt, err := oaque.RandomInZp(rand.Reader)
	if err != nil {
		return nil, nil, err
	}

	key, err := oaque.KeyGen(randomInt, params, masterKey, make(map[oaque.AttributeIndex]*big.Int))
	if err != nil {
		return nil, nil, err
	}

	hd := &HierarchyDescriptor{
		Nickname: nickname,
		Params:   params,
	}

	decryptionKey := &DecryptionKey{
		Hierarchy: hd,
		Key:       key,
		Permissions: &Permission{
			URI:  make(core.URIPath, 0),
			Time: make(core.TimePath, 0),
		},
	}

	return hd, decryptionKey, nil
}

func DelegateRaw(random io.Reader, hd *HierarchyDescriptor, from *DecryptionKey, perm *Permission) (*DecryptionKey, error) {
	return nil, nil
}

func CreateEntity(random io.Reader, hd *HierarchyDescriptor) (*EntityDescriptor, *EntitySecret, error) {
	return nil, nil, nil
}

func DelegateBroadening(random io.Reader, from *EntitySecret, to *EntityDescriptor, perm *Permission) (*BroadeningDelegation, error) {
	return nil, nil
}

func DelegateBroadeningWithKey(random io.Reader, from *DecryptionKey, to *EntityDescriptor, perm *Permission) (*BroadeningDelegationWithKey, error) {
	return nil, nil
}

func ResolveChain(first *BroadeningDelegationWithKey, rest []*BroadeningDelegation, to *EntitySecret) *DecryptionKey {
	return nil
}

func Encrypt(random io.Reader, hd *HierarchyDescriptor, perm *Permission, message []byte) (*EncryptedMessage, error) {
	e := PrepareEncryption(hd, perm)
	return e.Encrypt(random, message)
}

func GenerateEncryptedSymmetricKey(random io.Reader, hd *HierarchyDescriptor, perm *Permission, symm []byte) (*EncryptedSymmetricKey, error) {
	e := PrepareEncryption(hd, perm)
	return e.GenerateEncryptedSymmetricKey(random, symm)
}

func PrepareEncryption(hd *HierarchyDescriptor, perm *Permission) *Encryptor {
	attrs := perm.AttributeSet()
	return &Encryptor{
		Hierarchy:   hd,
		Permissions: perm,
		Precomputed: oaque.PrecomputeEncryption(hd.Params, attrs),
	}
}

func (e *Encryptor) Encrypt(random io.Reader, message []byte) (*EncryptedMessage, error) {
	var key [32]byte
	encryptedKey, err := e.GenerateEncryptedSymmetricKey(random, key[:])
	if err != nil {
		return nil, err
	}

	var nonce [24]byte
	output := make([]byte, len(message)+secretbox.Overhead)
	secretbox.Seal(output, message, &nonce, &key)

	return &EncryptedMessage{
		Key:     encryptedKey,
		Message: output,
	}, nil
}

func (e *Encryptor) GenerateEncryptedSymmetricKey(random io.Reader, symm []byte) (*EncryptedSymmetricKey, error) {
	_, hashesToKey := cryptutils.GenerateKey(symm)
	ct, err := oaque.EncryptPrecomputed(nil, e.Hierarchy.Params, e.Precomputed, hashesToKey)
	if err != nil {
		return nil, err
	}
	return &EncryptedSymmetricKey{
		Ciphertext:  ct,
		Permissions: e.Permissions,
	}, nil
}

func Decrypt(c *EncryptedMessage, key *DecryptionKey) []byte {
	d := PrepareDecryption(c.Key.Permissions, key)
	return d.Decrypt(c)
}

func DecryptSymmetricKey(c *EncryptedSymmetricKey, key *DecryptionKey, symm []byte) []byte {
	d := PrepareDecryption(c.Permissions, key)
	return d.DecryptSymmetricKey(c, symm)
}

func PrepareDecryption(perm *Permission, key *DecryptionKey) *Decryptor {
	attrs := perm.AttributeSet()
	childKey := oaque.DecryptionKey(key.Hierarchy.Params, key.Key, attrs)
	return (*Decryptor)(childKey)
}

func (d *Decryptor) Decrypt(c *EncryptedMessage) []byte {
	var sk [32]byte
	d.DecryptSymmetricKey(c.Key, sk[:])

	var nonce [24]byte
	output := make([]byte, len(c.Message)-secretbox.Overhead)
	message, ok := secretbox.Open(output, c.Message, &nonce, &sk)
	if !ok {
		return nil
	}
	return message
}

func (d *Decryptor) DecryptSymmetricKey(c *EncryptedSymmetricKey, symm []byte) []byte {
	key := (*oaque.PrivateKey)(d)
	hashesToKey := oaque.Decrypt(key, c.Ciphertext)
	return cryptutils.GTToSecretKey(hashesToKey, symm)
}
