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

type HierarchyDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

func (hd *HierarchyDescriptor) HashToZp() *big.Int {
	return cryptutils.HashToZp(hd.Params.Marshal())
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

func (p *Permission) AttributeSet() oaque.AttributeList {
	return core.AttributeSetFromPaths(p.URI, p.Time)
}

type EntityDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

type EntitySecret struct {
	Key        oaque.MasterKey
	Descriptor *EntityDescriptor
}

type BroadeningDelegation struct {
	Delegation *EncryptedMessage
	From       *EntityDescriptor
	To         *EntityDescriptor
}

type BroadeningDelegationWithKey struct {
	Key       *EncryptedMessage
	To        *EntityDescriptor
	Hierarchy *HierarchyDescriptor
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
	encryptedKey, encryptedMessage, err := core.HybridEncrypt(random, to.Params, oaque.PrecomputeEncryption(to.Params, attrs), key.Marshal())
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

func DelegateBroadeningWithKey(random io.Reader, from *DecryptionKey, to *EntityDescriptor, perm *Permission) (*BroadeningDelegationWithKey, error) {
	attrs := perm.AttributeSet()
	attrs[MaxURIDepth+TimeDepth] = from.Hierarchy.HashToZp()

	key, err := DelegateRaw(random, from, perm)
	if err != nil {
		return nil, err
	}

	// Encrypt key from "From" system under same attribute set in "To" system
	encryptedKey, encryptedMessage, err := core.HybridEncrypt(random, to.Params, oaque.PrecomputeEncryption(to.Params, attrs), key.Key.Marshal())
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

func ResolveChain(first *BroadeningDelegationWithKey, rest []*BroadeningDelegation, to *EntitySecret) *DecryptionKey {
	key := oaque.DecryptionKeyFromMaster(to.Descriptor.Params, to.Key, make(oaque.AttributeList))
	for i := len(rest) - 1; i >= 0; i-- {
		delegation := rest[i]
		perm := delegation.Delegation.Key.Permissions
		subkey := oaque.DecryptionKey(delegation.To.Params, key, perm.AttributeSet())
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
	subkey := oaque.DecryptionKey(first.To.Params, key, perm.AttributeSet())
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
	message, ok := core.HybridDecrypt(c.Key.Ciphertext, c.Message, (*oaque.PrivateKey)(d))
	if !ok {
		return nil
	}
	return message
}

func (d *Decryptor) DecryptSymmetricKey(c *EncryptedSymmetricKey, symm []byte) []byte {
	return core.DecryptSymmetricKey((*oaque.PrivateKey)(d), c.Ciphertext, symm)
}
