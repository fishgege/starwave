// Package starwave implements a library for applications wanting to use
// STARWAVE as a mechanism for key delegation.
package starwave

import (
	"crypto/rand"
	"io"
	"math/big"
	"time"

	"github.com/SoftwareDefinedBuildings/starwave/core"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/cryptutils"
	"github.com/SoftwareDefinedBuildings/starwave/crypto/oaque"
)

// HierarchyDescriptor is the public information representing a hierarchy.
type HierarchyDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

// HashToZp() hashes the hierarchy, independent of its nickname, to a single
// number from 0 to p - 1.
func (hd *HierarchyDescriptor) HashToZp() *big.Int {
	return cryptutils.HashToZp(hd.Params.Marshal())
}

// DecryptionKey represents a key that can be used to decrypt messages on a set
// of resources and time range.
type DecryptionKey struct {
	Hierarchy   *HierarchyDescriptor
	Key         *oaque.PrivateKey
	Permissions *Permission
}

// Permission represents a set of resources bundled with a time range.
type Permission struct {
	URI  core.URIPath
	Time core.TimePath
}

// ParsePermission converts a URI string and time into the permission
// representing the set of resources represented by the string, and the most
// granular time range represented by the time.
func ParsePermission(uri string, time time.Time) (*Permission, error) {
	uriPath, err := core.ParseURI(uri)
	if err != nil {
		return nil, err
	}
	timePath, err := core.ParseTime(time)
	if err != nil {
		return nil, err
	}
	return &Permission{
		URI:  uriPath,
		Time: timePath,
	}, nil
}

// ParsePermissionFromPath is similar to ParsePermission, except that it
// supports large time ranges by virtue of accepting an explicit path.
func ParsePermissionFromPath(uriPrefix []string, timePrefix []uint16) (*Permission, error) {
	uriPath, err := core.ParseURIFromPath(uriPrefix)
	if err != nil {
		return nil, err
	}
	timePath, err := core.ParseTimeFromPath(timePrefix)
	if err != nil {
		return nil, err
	}
	return &Permission{
		URI:  uriPath,
		Time: timePath,
	}, nil
}

// AttributeSet converts a permission into an attribute list for use with OAQUE.
func (p *Permission) AttributeSet() oaque.AttributeList {
	return core.AttributeSetFromPaths(p.URI, p.Time)
}

// EntityDescriptor represents the publicly available information describing an
// entity. It is only used for broadening permissions.
type EntityDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

// EntitySecret represents the secret information that an entity possesses.
type EntitySecret struct {
	Key        oaque.MasterKey
	Descriptor *EntityDescriptor
}

// BroadeningDelegation represents a delegation of permissions, that allows
// the grantee to "inherit" keys for narrower permissions obtained by the
// granter.
type BroadeningDelegation struct {
	Delegation *EncryptedMessage
	From       *EntityDescriptor
	To         *EntityDescriptor
}

// BroadeningDelegationWithKey represents the transfer of a key on some
// permissions, allowing entities with a chain of BroadeningDelegations to the
// grantee to inherit the transferred key.
type BroadeningDelegationWithKey struct {
	Key       *EncryptedMessage
	To        *EntityDescriptor
	Hierarchy *HierarchyDescriptor
}

// EncryptedSymmetricKey represents a symmetric key encrypted using OAQUE. This
// is a useful primitive for applications that repeatedly publish on the same
// attribute set, allowing the asymmetric OAQUE-based encryption to be performed
// only once, and the actual messages on that attribute set to be encrypted with
// the same symmetric key.
type EncryptedSymmetricKey struct {
	Ciphertext  *oaque.Ciphertext
	Permissions *Permission
}

// EncryptedMessage represents a symmetric key encrypted using OAQUE, and a
// message encrypted using that symmetric key.
type EncryptedMessage struct {
	Key     *EncryptedSymmetricKey
	Message []byte
}

// Encryptor represents an object storing cached state that allows fast
// encryption for a given attribute set. You can think of this as a middle
// ground between encrypting a symmetric key once and reusing the symmetric
// key (which depends on some infrastructure to store the encrypted symmetric
// key), and encrypting a symmetric key from scratch for every message.
type Encryptor struct {
	Hierarchy   *HierarchyDescriptor
	Permissions *Permission
	Precomputed *oaque.PreparedAttributeList
}

// Decryptor represents an object storing cached state that allows fast
// decryption for a given attribute set. In particular, it caches the generation
// of the private key for the exact attribute set.
type Decryptor oaque.PrivateKey

const (
	// MaxURIDepth is the maximum depth of a URI in STARWAVE.
	MaxURIDepth = core.MaxURILength

	// TimeDepth is the number of OAQUE slots to represent a fully qualified
	// time.
	TimeDepth = core.MaxTimeLength
)

// CreateHierarchy creates a new STARWAVE hierarchy.
func CreateHierarchy(random io.Reader, nickname string) (*HierarchyDescriptor, *DecryptionKey, error) {
	numSlots := MaxURIDepth + TimeDepth

	params, masterKey, err := oaque.Setup(rand.Reader, numSlots)
	if err != nil {
		return nil, nil, err
	}

	randomInt, err := oaque.RandomInZp(random)
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

// DelegateRaw takes as input a decryption key, and outputs another decryption
// key whose capability is qualified. The returned key is safe to give to
// another entity.
func DelegateRaw(random io.Reader, from *DecryptionKey, perm *Permission) (*DecryptionKey, error) {
	attrs := perm.AttributeSet()

	t, err := oaque.RandomInZp(random)
	if err != nil {
		return nil, err
	}
	qualified, err := oaque.QualifyKey(t, from.Hierarchy.Params, from.Key, attrs)
	if err != nil {
		return nil, err
	}

	return &DecryptionKey{
		Hierarchy:   from.Hierarchy,
		Key:         qualified,
		Permissions: perm,
	}, nil

	return nil, nil
}

// CreateEntity creates a new entity for receiving and creating broadening
// delegations. This is only used with permission inheritance (broadening
// delegation).
func CreateEntity(random io.Reader, nickname string) (*EntityDescriptor, *EntitySecret, error) {
	// One extra slot at the end, for the hierarchy name
	numSlots := MaxURIDepth + TimeDepth + 1

	params, masterKey, err := oaque.Setup(rand.Reader, numSlots)
	if err != nil {
		return nil, nil, err
	}

	entity := &EntityDescriptor{
		Nickname: nickname,
		Params:   params,
	}

	secret := &EntitySecret{
		Key:        masterKey,
		Descriptor: entity,
	}

	return entity, secret, nil
}

// DelegateBroadening creates a delegation with permission inheritance to
// another entity. If the source entity receives a key for a "narrower"
// set of permissions, the destination entity inherits that key.
func DelegateBroadening(random io.Reader, hd *HierarchyDescriptor, from *EntitySecret, to *EntityDescriptor, perm *Permission) (*BroadeningDelegation, error) {
	attrs := perm.AttributeSet()
	attrs[MaxURIDepth+TimeDepth] = hd.HashToZp()

	s, err := oaque.RandomInZp(random)
	if err != nil {
		return nil, err
	}

	key, err := oaque.KeyGen(s, hd.Params, from.Key, attrs)
	if err != nil {
		return nil, err
	}

	// Encrypt key from "From" system under same attribute set in "To" system
	encryptedKey, encryptedMessage, err := core.HybridEncrypt(random, to.Params, oaque.PrepareAttributeSet(to.Params, attrs), key.Marshal())
	if err != nil {
		return nil, err
	}

	return &BroadeningDelegation{
		Delegation: &EncryptedMessage{
			Key: &EncryptedSymmetricKey{
				Ciphertext:  encryptedKey,
				Permissions: perm,
			},
			Message: encryptedMessage,
		},
		From: from.Descriptor,
		To:   to,
	}, nil
}

// DelegateBroadeningWithKey delegates a key to an entity in a way that is
// compatible with permission inheritance. If the destination entity has made
// broadening delegations to other entities, they will inherit this key if it
// is "narrower" than the permissions conveyed in those broadening delegations.
func DelegateBroadeningWithKey(random io.Reader, from *DecryptionKey, to *EntityDescriptor, perm *Permission) (*BroadeningDelegationWithKey, error) {
	attrs := perm.AttributeSet()
	attrs[MaxURIDepth+TimeDepth] = from.Hierarchy.HashToZp()

	key, err := DelegateRaw(random, from, perm)
	if err != nil {
		return nil, err
	}

	// Encrypt key from "From" system under same attribute set in "To" system
	encryptedKey, encryptedMessage, err := core.HybridEncrypt(random, to.Params, oaque.PrepareAttributeSet(to.Params, attrs), key.Key.Marshal())
	if err != nil {
		return nil, err
	}

	return &BroadeningDelegationWithKey{
		Key: &EncryptedMessage{
			Key: &EncryptedSymmetricKey{
				Ciphertext:  encryptedKey,
				Permissions: perm,
			},
			Message: encryptedMessage,
		},
		To: to,
	}, nil
}

// ResolveChain resolves a chain of broadening delegations, the first of which
// contains a key. In other words, it performs permission inheritance.
func ResolveChain(first *BroadeningDelegationWithKey, rest []*BroadeningDelegation, to *EntitySecret) *DecryptionKey {
	key := oaque.NonDelegableKeyFromMaster(to.Descriptor.Params, to.Key, make(oaque.AttributeList))
	for i := len(rest) - 1; i >= 0; i-- {
		delegation := rest[i]
		perm := delegation.Delegation.Key.Permissions
		subkey := oaque.NonDelegableKey(delegation.To.Params, key, perm.AttributeSet())
		nextKeyBytes, ok := core.HybridDecrypt(delegation.Delegation.Key.Ciphertext, delegation.Delegation.Message, subkey)
		if !ok {
			return nil
		}
		key, ok = key.Unmarshal(nextKeyBytes)
		if !ok {
			return nil
		}
	}

	perm := first.Key.Key.Permissions
	subkey := oaque.NonDelegableKey(first.To.Params, key, perm.AttributeSet())
	finalKeyBytes, ok := core.HybridDecrypt(first.Key.Key.Ciphertext, first.Key.Message, subkey)
	if !ok {
		return nil
	}
	key, ok = key.Unmarshal(finalKeyBytes)
	if !ok {
		return nil
	}
	return &DecryptionKey{
		Hierarchy:   first.Hierarchy,
		Key:         key,
		Permissions: perm,
	}
}

// Encrypt takes a message and encrypts it under a set of permissions. Only with
// a decryption key for those permissions or a broader set of permissions (an
// attribute subset) can the message be decrypted.
func Encrypt(random io.Reader, hd *HierarchyDescriptor, perm *Permission, message []byte) (*EncryptedMessage, error) {
	e := PrepareEncryption(hd, perm)
	return e.Encrypt(random, message)
}

// GenerateEncryptedSymmetricKey fills in the provided buffer "symm" with random
// bytes (for use as a symmetric key), and returns a ciphertext of that key,
// encrypted under the specified permissions. Note that the space of ciphertexts
// has 256 bits of entropy, so symm should be at most 32 bytes.
func GenerateEncryptedSymmetricKey(random io.Reader, hd *HierarchyDescriptor, perm *Permission, symm []byte) (*EncryptedSymmetricKey, error) {
	e := PrepareEncryption(hd, perm)
	return e.GenerateEncryptedSymmetricKey(random, symm)
}

// PrepareEncryption caches intermediate results for encryption under the
// specified set of permissions, and returns an Encryptor containing those
// cached results.
func PrepareEncryption(hd *HierarchyDescriptor, perm *Permission) *Encryptor {
	attrs := perm.AttributeSet()
	return &Encryptor{
		Hierarchy:   hd,
		Permissions: perm,
		Precomputed: oaque.PrepareAttributeSet(hd.Params, attrs),
	}
}

// Encrypt is the same as the general "Encrypt" function, except that it uses
// cached results in the Encryptor to speed up the process.
func (e *Encryptor) Encrypt(random io.Reader, message []byte) (*EncryptedMessage, error) {
	encryptedKey, encryptedMessage, err := core.HybridEncrypt(random, e.Hierarchy.Params, e.Precomputed, message)
	if err != nil {
		return nil, err
	}

	return &EncryptedMessage{
		Key: &EncryptedSymmetricKey{
			Ciphertext:  encryptedKey,
			Permissions: e.Permissions,
		},
		Message: encryptedMessage,
	}, nil
}

// GenerateEncryptedSymmetricKey is the same as the general
// "GenerateEncryptedSymmetricKey", except that it uses cached results in the
// Encryptor to speed up the process.
func (e *Encryptor) GenerateEncryptedSymmetricKey(random io.Reader, symm []byte) (*EncryptedSymmetricKey, error) {
	ct, err := core.GenerateEncryptedSymmetricKey(random, e.Hierarchy.Params, e.Precomputed, symm)
	if err != nil {
		return nil, err
	}
	return &EncryptedSymmetricKey{
		Ciphertext:  ct,
		Permissions: e.Permissions,
	}, nil
}

// Decrypt converts an encrypted message into plaintext, as long as the provided
// key has at least the necessary capability to decrypt the message.
func Decrypt(c *EncryptedMessage, key *DecryptionKey) []byte {
	d := PrepareDecryption(c.Key.Permissions, key)
	return d.Decrypt(c)
}

// DecryptSymmetricKey is like Decrypt, except that the input is only an
// encrypted symmetric key instead of an encrypted message.
func DecryptSymmetricKey(c *EncryptedSymmetricKey, key *DecryptionKey, symm []byte) []byte {
	d := PrepareDecryption(c.Permissions, key)
	return d.DecryptSymmetricKey(c, symm)
}

// PrepareDecryption caches intermediate results for decrypting messages
// encrypted with exactly the set of permissions provided as the first argument.
func PrepareDecryption(perm *Permission, key *DecryptionKey) *Decryptor {
	attrs := perm.AttributeSet()
	childKey := oaque.NonDelegableKey(key.Hierarchy.Params, key.Key, attrs)
	return (*Decryptor)(childKey)
}

// Decrypt is the same as the general "Decrypt" function, except that it uses
// cached results in the decryptor to speed up the process.
func (d *Decryptor) Decrypt(c *EncryptedMessage) []byte {
	message, ok := core.HybridDecrypt(c.Key.Ciphertext, c.Message, (*oaque.PrivateKey)(d))
	if !ok {
		return nil
	}
	return message
}

// DecryptSymmetricKey is the same as the general "DecryptSymmetricKey"
// function, except that it uses cached results in the decryptor to speed up the
// process.
func (d *Decryptor) DecryptSymmetricKey(c *EncryptedSymmetricKey, symm []byte) []byte {
	return core.DecryptSymmetricKey((*oaque.PrivateKey)(d), c.Ciphertext, symm)
}
