// Package starwave implements a library for applications wanting to use
// STARWAVE as a mechanism for key delegation.
package starwave

import (
	"crypto/rand"
	"fmt"
	"io"
	"math/big"
	"time"

	"github.com/ucbrise/starwave/core"
	"github.com/ucbrise/starwave/crypto/cryptutils"
	"github.com/ucbrise/starwave/crypto/oaque"
)

// Types of keys
const (
	KeyTypeMaster = iota
	KeyTypeDecryption
	KeyTypeSignature
)

// Prefixes used to construct attribute lists
var (
	DecryptionPrefix = []byte{0x0}
	SignaturePrefix  = []byte{0x1}
)

func keyTypeCompatible(from int, to int) bool {
	return from == KeyTypeMaster || from == to
}

// HierarchyDescriptor is the public information representing a hierarchy.
type HierarchyDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

// HashToZp hashes the hierarchy, independent of its nickname, to a single
// number from 0 to p - 1.
func (hd *HierarchyDescriptor) HashToZp() *big.Int {
	return cryptutils.HashToZp(hd.Params.Marshal())
}

// DecryptionKey represents a key that can be used to decrypt/sign messages on a
// set of resources and time range.
type DecryptionKey struct {
	Hierarchy   *HierarchyDescriptor
	Key         *oaque.PrivateKey
	Permissions *Permission
	KeyType     int
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

// Contains returns true if this permission also conveys the set of permissions
// passed as an argument.
func (p *Permission) Contains(other *Permission) bool {
	return core.IsURIPrefix(p.URI, other.URI) && core.IsTimePrefix(p.Time, other.Time)
}

// Equals returns true if this permission is equal to the permission passed as
// an argument
func (p *Permission) Equals(other *Permission) bool {
	return p.Contains(other) && other.Contains(p)
}

// AttributeSet converts a permission into an attribute list for use with OAQUE.
func (p *Permission) AttributeSet(keyType int) oaque.AttributeList {
	var prefix []byte
	switch keyType {
	case KeyTypeDecryption:
		prefix = DecryptionPrefix
	case KeyTypeSignature:
		prefix = SignaturePrefix
	default:
		panic(fmt.Sprintf("Unknown key type %d", keyType))
	}
	return core.AttributeSetFromPaths(p.URI, p.Time, prefix)
}

// EntityDescriptor represents the publicly available information describing an
// entity. It is only used for broadening permissions.
type EntityDescriptor struct {
	Nickname string
	Params   *oaque.Params
}

// EntitySecret represents the secret information that an entity possesses.
type EntitySecret struct {
	Key        *oaque.MasterKey
	Descriptor *EntityDescriptor
}

// EncryptedSymmetricKey represents a symmetric key encrypted using OAQUE. This
// is a useful primitive for applications that repeatedly publish on the same
// attribute set, allowing the asymmetric OAQUE-based encryption to be performed
// only once, and the actual messages on that attribute set to be encrypted with
// the same symmetric key.
type EncryptedSymmetricKey struct {
	Ciphertext  *oaque.Ciphertext
	Signature   *oaque.Signature
	Permissions *Permission
}

// EncryptedMessage represents a symmetric key encrypted using OAQUE, and a
// message encrypted using that symmetric key.
type EncryptedMessage struct {
	Key     *EncryptedSymmetricKey
	IV      [24]byte
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
	SigningKey  *oaque.PrivateKey
	Signer      *oaque.PreparedAttributeList
}

// Decryptor represents an object storing cached state that allows fast
// decryption for a given attribute set. In particular, it caches the generation
// of the private key for the exact attribute set.
type Decryptor struct {
	Params   *oaque.Params
	Key      *oaque.PrivateKey
	Verifier *oaque.PreparedAttributeList
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

// FullDelegation consists of a broadening delegation, plus some keys that are
// the result of narrowing delegations. A single FullDelegation conveys
// keys for a single Permission.
type FullDelegation struct {
	Permissions *Permission
	Broad       *BroadeningDelegation
	Narrow      []*BroadeningDelegationWithKey
}

// DelegationBundle is a set of FullDelegations that are serialized together.
// This is useful for delegations that span multiple units of time. Each
// individual delegation must be on a disjoint Permission.
type DelegationBundle struct {
	Delegations []*FullDelegation
}

// Compress elides information that could probably be obtained from
// metadata included with the delegations: To, From, and Hierarchy fields
func (deleg *FullDelegation) Compress() {
	if deleg.Broad != nil {
		deleg.Broad.From = nil
		deleg.Broad.To = nil
	}
	for _, narrow := range deleg.Narrow {
		narrow.Hierarchy = nil
		narrow.To = nil
	}
}

// Decompress fills in fields that were elided.
func (deleg *FullDelegation) Decompress(from *EntityDescriptor, to *EntityDescriptor, hd *HierarchyDescriptor) {
	if deleg.Broad != nil {
		deleg.Broad.From = from
		deleg.Broad.To = to
	}
	for _, narrow := range deleg.Narrow {
		narrow.Hierarchy = hd
		narrow.To = to
	}
}

// Compress elides information that could probably be obtained from
// metadata included with the delegations: To, From, and Hierarchy fields
func (db *DelegationBundle) Compress() {
	for _, deleg := range db.Delegations {
		deleg.Compress()
	}
}

// Decompress fills in fields that were elided.
func (db *DelegationBundle) Decompress(from *EntityDescriptor, to *EntityDescriptor, hd *HierarchyDescriptor) {
	for _, deleg := range db.Delegations {
		deleg.Decompress(from, to, hd)
	}
}

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

	params, masterKey, err := oaque.Setup(rand.Reader, numSlots, true)
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
		KeyType: KeyTypeMaster,
	}

	return hd, decryptionKey, nil
}

// DelegateRaw takes as input a decryption key, and outputs another decryption
// key whose capability is qualified. The returned key is safe to give to
// another entity.
func DelegateRaw(random io.Reader, from *DecryptionKey, perm *Permission, keyType int) (*DecryptionKey, error) {
	if !keyTypeCompatible(from.KeyType, keyType) {
		panic("Incompatible key type")
	}
	attrs := perm.AttributeSet(keyType)

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
		KeyType:     from.KeyType,
	}, nil

	return nil, nil
}

// CreateEntity creates a new entity for receiving and creating broadening
// delegations. This is only used with permission inheritance (broadening
// delegation).
func CreateEntity(random io.Reader, nickname string) (*EntityDescriptor, *EntitySecret, error) {
	// One extra slot at the end, for the hierarchy name
	numSlots := MaxURIDepth + TimeDepth + 1

	params, masterKey, err := oaque.Setup(rand.Reader, numSlots, false)
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
func DelegateBroadening(random io.Reader, hd *HierarchyDescriptor, from *EntitySecret, to *EntityDescriptor, perm *Permission, keyType int) (*BroadeningDelegation, error) {
	attrs := perm.AttributeSet(keyType)
	attrs[MaxURIDepth+TimeDepth] = hd.HashToZp()

	s, err := oaque.RandomInZp(random)
	if err != nil {
		return nil, err
	}

	key, err := oaque.KeyGen(s, from.Descriptor.Params, from.Key, attrs)
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
func DelegateBroadeningWithKey(random io.Reader, from *DecryptionKey, to *EntityDescriptor, perm *Permission, keyType int) (*BroadeningDelegationWithKey, error) {
	if !keyTypeCompatible(from.KeyType, keyType) {
		panic("Incompatible key type")
	}
	attrs := perm.AttributeSet(keyType)
	attrs[MaxURIDepth+TimeDepth] = from.Hierarchy.HashToZp()

	key, err := DelegateRaw(random, from, perm, keyType)
	if err != nil {
		return nil, err
	}

	// Encrypt the decryption key under same attribute set in "To" system
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
		To:        to,
		Hierarchy: from.Hierarchy,
	}, nil
}

// ResolveChain resolves a chain of broadening delegations, the first of which
// contains a key. In other words, it performs permission inheritance.
func ResolveChain(first *BroadeningDelegationWithKey, rest []*BroadeningDelegation, to *EntitySecret, keyType int) *DecryptionKey {
	key := oaque.NonDelegableKeyFromMaster(to.Descriptor.Params, to.Key, make(oaque.AttributeList))
	for i := len(rest) - 1; i >= 0; i-- {
		delegation := rest[i]
		perm := delegation.Delegation.Key.Permissions
		attrs := perm.AttributeSet(keyType)
		attrs[MaxURIDepth+TimeDepth] = first.Hierarchy.HashToZp()
		subkey := oaque.NonDelegableKey(delegation.To.Params, key, attrs)
		nextKeyBytes, ok := core.HybridDecrypt(delegation.Delegation.Key.Ciphertext, delegation.Delegation.Message, subkey, &delegation.Delegation.IV)
		if !ok {
			return nil
		}
		ok = key.Unmarshal(nextKeyBytes)
		if !ok {
			return nil
		}
	}

	perm := first.Key.Key.Permissions
	attrs := perm.AttributeSet(keyType)
	attrs[MaxURIDepth+TimeDepth] = first.Hierarchy.HashToZp()
	subkey := oaque.NonDelegableKey(first.To.Params, key, attrs)
	finalKeyBytes, ok := core.HybridDecrypt(first.Key.Key.Ciphertext, first.Key.Message, subkey, &first.Key.IV)
	if !ok {
		return nil
	}
	ok = key.Unmarshal(finalKeyBytes)
	if !ok {
		return nil
	}
	return &DecryptionKey{
		Hierarchy:   first.Hierarchy,
		Key:         key,
		Permissions: perm,
		KeyType:     keyType,
	}
}

// Encrypt takes a message and encrypts it under a set of permissions. Only with
// a decryption key for those permissions or a broader set of permissions (an
// attribute subset) can the message be decrypted.
func Encrypt(random io.Reader, hd *HierarchyDescriptor, perm *Permission, signingKey *DecryptionKey, message []byte) (*EncryptedMessage, error) {
	e := PrepareEncryption(hd, perm, signingKey)
	return e.Encrypt(random, message)
}

// EncryptWithSymmetricKey is like Encrypt, but allows you to reuse the same
// symmetric key (eliminating expensive OAQUE encryptions).
func EncryptWithSymmetricKey(random io.Reader, esymm *EncryptedSymmetricKey, symm []byte, message []byte) (*EncryptedMessage, error) {
	res := &EncryptedMessage{
		Key:     esymm,
		Message: nil,
	}
	_, err := rand.Read(res.IV[:])
	if err != nil {
		return nil, err
	}

	var key [32]byte
	copy(key[:], symm[:len(key)])

	res.Message = core.EncryptWithSymmetricKey(random, &key, &res.IV, message)
	return res, nil
}

// GenerateEncryptedSymmetricKey fills in the provided buffer "symm" with random
// bytes (for use as a symmetric key), and returns a ciphertext of that key,
// encrypted under the specified permissions. Note that the space of ciphertexts
// has 256 bits of entropy, so symm should be at most 32 bytes.
func GenerateEncryptedSymmetricKey(random io.Reader, hd *HierarchyDescriptor, perm *Permission, signingKey *DecryptionKey, symm []byte) (*EncryptedSymmetricKey, error) {
	e := PrepareEncryption(hd, perm, signingKey)
	return e.GenerateEncryptedSymmetricKey(random, symm)
}

// PrepareEncryption caches intermediate results for encryption under the
// specified set of permissions, and returns an Encryptor containing those
// cached results.
func PrepareEncryption(hd *HierarchyDescriptor, perm *Permission, key *DecryptionKey) *Encryptor {
	attrs := perm.AttributeSet(KeyTypeDecryption)
	signingAttrs := perm.AttributeSet(KeyTypeSignature)
	encryptor := &Encryptor{
		Hierarchy:   hd,
		Permissions: perm,
		Precomputed: oaque.PrepareAttributeSet(hd.Params, attrs),
	}
	if key != nil {
		if !keyTypeCompatible(key.KeyType, KeyTypeDecryption) {
			panic("Incorrect key type")
		}
		encryptor.SigningKey = oaque.NonDelegableKey(hd.Params, key.Key, signingAttrs)
		encryptor.Signer = oaque.PrepareAttributeSet(hd.Params, signingAttrs)
	}
	return encryptor
}

// Encrypt is the same as the general "Encrypt" function, except that it uses
// cached results in the Encryptor to speed up the process.
func (e *Encryptor) Encrypt(random io.Reader, message []byte) (*EncryptedMessage, error) {
	encryptedKey, encryptedMessage, err := core.HybridEncrypt(random, e.Hierarchy.Params, e.Precomputed, message)
	if err != nil {
		return nil, err
	}

	em := &EncryptedMessage{
		Key: &EncryptedSymmetricKey{
			Ciphertext:  encryptedKey,
			Signature:   nil,
			Permissions: e.Permissions,
		},
		Message: encryptedMessage,
	}

	if e.SigningKey != nil {
		em.Key.Signature, err = oaque.SignPrecomputed(nil, e.Hierarchy.Params, e.SigningKey, e.Permissions.AttributeSet(KeyTypeSignature), e.Signer, cryptutils.HashToZp(message))
		if err != nil {
			return nil, err
		}
	}

	return em, nil
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
func Decrypt(c *EncryptedMessage, key *DecryptionKey, checkSignature bool) []byte {
	d := PrepareDecryption(c.Key.Permissions, key)
	return d.Decrypt(c, checkSignature)
}

// DecryptWithSymmetricKey is like Decrypt, but allows you to reuse the same
// symmetric key (avoiding expensive OAQUE decryptions).
func DecryptWithSymmetricKey(c *EncryptedMessage, key *[32]byte) []byte {
	message, ok := core.DecryptWithSymmetricKey(key, &c.IV, c.Message)
	if !ok {
		return nil
	}
	return message
}

// DecryptSymmetricKey is like Decrypt, except that the input is only an
// encrypted symmetric key instead of an encrypted message.
func DecryptSymmetricKey(c *EncryptedSymmetricKey, key *DecryptionKey, symm []byte, checkSignature bool) []byte {
	d := PrepareDecryption(c.Permissions, key)
	return d.DecryptSymmetricKey(c, symm, checkSignature)
}

// PrepareDecryption caches intermediate results for decrypting messages
// encrypted with exactly the set of permissions provided as the first argument.
func PrepareDecryption(perm *Permission, key *DecryptionKey) *Decryptor {
	if !keyTypeCompatible(key.KeyType, KeyTypeDecryption) {
		panic("Incorrect key type")
	}
	attrs := perm.AttributeSet(KeyTypeDecryption)
	childKey := oaque.NonDelegableKey(key.Hierarchy.Params, key.Key, attrs)
	attrs = perm.AttributeSet(KeyTypeSignature)
	precomputed := oaque.PrepareAttributeSet(key.Hierarchy.Params, attrs)
	return &Decryptor{
		Params:   key.Hierarchy.Params,
		Key:      childKey,
		Verifier: precomputed,
	}
}

// Decrypt is the same as the general "Decrypt" function, except that it uses
// cached results in the decryptor to speed up the process.
func (d *Decryptor) Decrypt(c *EncryptedMessage, checkSignature bool) []byte {
	ct := c.Key.Ciphertext
	if checkSignature {
		ok := oaque.VerifyPrecomputed(d.Params, d.Verifier, c.Key.Signature, cryptutils.HashToZp(ct.Marshal()))
		if !ok {
			return nil
		}
	}
	message, ok := core.HybridDecrypt(ct, c.Message, d.Key, &c.IV)
	if !ok {
		return nil
	}
	return message
}

// DecryptSymmetricKey is the same as the general "DecryptSymmetricKey"
// function, except that it uses cached results in the decryptor to speed up the
// process.
func (d *Decryptor) DecryptSymmetricKey(c *EncryptedSymmetricKey, symm []byte, checkSignature bool) []byte {
	ct := c.Ciphertext
	if checkSignature {
		ok := oaque.VerifyPrecomputed(d.Params, d.Verifier, c.Signature, cryptutils.HashToZp(ct.Marshal()))
		if !ok {
			return nil
		}
	}
	return core.DecryptSymmetricKey(d.Key, c.Ciphertext, symm)
}

// DeriveKey takes as input a chain of delegations, and tries to derive the key
// for a Permission.
func DeriveKey(chain []*DelegationBundle, perm *Permission, me *EntitySecret, keyType int) *DecryptionKey {
	// First step: reduce the chain of DelegationBundles into a chain of
	// FullDelegations. This can be done easily, because the individual
	// delegations in a delegation bundle are disjoint.
	delegs := make([]*FullDelegation, len(chain))
thinchain:
	for i, bundle := range chain {
		for _, deleg := range bundle.Delegations {
			if deleg.Permissions.Contains(perm) {
				delegs[i] = deleg
				continue thinchain
			}
		}
		// If we reach this point, then the intersection of permissions is
		// does not contain the requested permission.
		return nil
	}

	var start *BroadeningDelegationWithKey
	var rest []*BroadeningDelegation

	// Second step: check for the nearest key that can be reached using only
	// broadening delegations.
loop:
	for i := len(delegs) - 1; i >= 0; i-- {
		deleg := delegs[i]
		for _, narrow := range deleg.Narrow {
			nperm := narrow.Key.Key.Permissions
			if nperm.Contains(perm) {
				start = narrow
				rest = make([]*BroadeningDelegation, len(delegs)-(i+1))
				for j := range rest {
					rest[j] = delegs[j+(i+1)].Broad
				}
				break loop
			}
		}
		// No keys in this delegation that I can access, so go to the previous
		// delegation. First, we must check if there is a previous delegation.
		if i == 0 {
			return nil
		}
		// Next, we must check if it's a "broadening" delegation that we can
		// traverse.
		if deleg.Broad != nil && !deleg.Permissions.Contains(delegs[i-1].Permissions) {
			// This is not a broadening link, so we have to give up
			return nil
		}
	}

	return ResolveChain(start, rest, me, keyType)
}

func PermissionRange(uri string, timeStart time.Time, timeEnd time.Time) ([]*Permission, error) {
	uripath, err := core.ParseURI(uri)
	if err != nil {
		return nil, err
	}
	times, err := core.TimeRange(timeStart, timeEnd)
	if err != nil {
		return nil, err
	}
	perms := make([]*Permission, len(times))
	for i, timepath := range times {
		perms[i] = &Permission{
			URI:  uripath,
			Time: timepath,
		}
	}
	return perms, nil
}

// DelegateFull creates a full delegation, granting a key for broadening, while
// providing keys that are available right now.
func DelegateFull(random io.Reader, hd *HierarchyDescriptor, from *EntitySecret, keys []*DecryptionKey, to *EntityDescriptor, perm *Permission, keyType int) (*FullDelegation, error) {
	fd := new(FullDelegation)
	fd.Permissions = perm

	gotExactKey := false

	// Now, of the provided keys, check which ones can provide at least parts of
	// the specified permissions.
	for _, key := range keys {
		if !keyTypeCompatible(key.KeyType, keyType) {
			continue
		}
		kperm := key.Permissions
		if kperm.Contains(perm) {
			// We can generate the key exactly.
			nkey, err := DelegateBroadeningWithKey(random, key, to, perm, keyType)
			if err != nil {
				return nil, err
			}
			fd.Narrow = []*BroadeningDelegationWithKey{nkey}
			gotExactKey = true
			break
		} else if core.IsURIPrefix(kperm.URI, perm.URI) && core.IsTimePrefix(perm.Time, kperm.Time) {
			// We can generate a partial key
			nkey, err := DelegateBroadeningWithKey(random, key, to, &Permission{
				URI:  perm.URI,
				Time: kperm.Time,
			}, keyType)
			if err != nil {
				return nil, err
			}
			fd.Narrow = append(fd.Narrow, nkey)
		} else if core.IsURIPrefix(perm.URI, kperm.URI) && core.IsTimePrefix(kperm.Time, perm.Time) {
			// We can generate a partial key
			nkey, err := DelegateBroadeningWithKey(random, key, to, &Permission{
				URI:  kperm.URI,
				Time: perm.Time,
			}, keyType)
			if err != nil {
				return nil, err
			}
			fd.Narrow = append(fd.Narrow, nkey)
		}
	}

	if !gotExactKey {
		var err error
		fd.Broad, err = DelegateBroadening(random, hd, from, to, perm, keyType)
		if err != nil {
			return nil, err
		}
	}

	return fd, nil
}

func ExtractKeys(db *DelegationBundle, me *EntitySecret, keyType int) []*DecryptionKey {
	var res []*DecryptionKey
	for _, deleg := range db.Delegations {
		for _, narrow := range deleg.Narrow {
			key := ResolveChain(narrow, nil, me, keyType)
			if key != nil {
				res = append(res, key)
			}
		}
	}
	return res
}

// DelegateBundle performs multiple full delegations over a resource and time
// range.
func DelegateBundle(random io.Reader, hd *HierarchyDescriptor, from *EntitySecret, keys []*DecryptionKey, to *EntityDescriptor, uri string, start time.Time, end time.Time, keyType int) (*DelegationBundle, error) {
	perms, err := PermissionRange(uri, start, end)
	if err != nil {
		return nil, err
	}

	db := new(DelegationBundle)
	db.Delegations = make([]*FullDelegation, len(perms))
	for i, perm := range perms {
		db.Delegations[i], err = DelegateFull(random, hd, from, keys, to, perm, keyType)
		if err != nil {
			return nil, err
		}
	}

	return db, nil
}
