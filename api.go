package starwave

import "io"

type HierarchyDescriptor struct {
	// TODO
}

type DecryptionKey struct {
	// TODO
}

type Permission struct {
	// TODO
}

type EntityDescriptor struct {
	// TODO
}

type EntitySecret struct {
	// TODO
}

type BroadeningDelegation struct {
	// TODO
}

type BroadeningDelegationWithKey struct {
	// TODO
}

type Ciphertext struct {
	// TODO
}

type Encryptor struct {
	// TODO
}

type Decryptor struct {
	// TODO
}

func CreateHierarchy(random io.Reader) (*HierarchyDescriptor, *DecryptionKey, error) {
	return nil, nil, nil
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

func Encrypt(random io.Reader, hd *HierarchyDescriptor, perm *Permission, message []byte) (*Ciphertext, error) {
	return nil, nil
}

func PrecomputeEncryption(hd *HierarchyDescriptor, perm *Permission) *Encryptor {
	return nil
}

func (e *Encryptor) Encrypt(random io.Reader, message []byte) (*Ciphertext, error) {
	return nil, nil
}

func Decrypt(c *Ciphertext, key *DecryptionKey) []byte {
	return nil
}

func PrecomputeDecryption(perm *Permission, key *DecryptionKey) *Decryptor {
	return nil
}

func (d *Decryptor) Decrypt(c *Ciphertext) []byte {
	return nil
}
