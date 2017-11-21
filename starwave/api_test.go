package starwave

import (
	"bytes"
	"crypto/rand"
	"testing"
	"time"
)

func randomMessageHelper(t *testing.T) []byte {
	message := make([]byte, 1027)
	_, err := rand.Read(message)
	if err != nil {
		t.Fatal(err)
	}
	return message
}

func createEntityHelper(t *testing.T, nickname string) (*EntityDescriptor, *EntitySecret) {
	entity, secret, err := CreateEntity(rand.Reader, nickname)
	if err != nil {
		t.Fatal(err)
	}
	return entity, secret
}

func TestSimpleMessage(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	key, err := DelegateRaw(rand.Reader, master, perm)
	if err != nil {
		t.Fatal(err)
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestExplicitHybrid(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermission("a/b/c/", time.Now())
	if err != nil {
		t.Fatal(err)
	}

	key, err := DelegateRaw(rand.Reader, master, perm)
	if err != nil {
		t.Fatal(err)
	}

	symm := make([]byte, 32)
	esymm, err := GenerateEncryptedSymmetricKey(rand.Reader, hierarchy, perm, symm)
	if err != nil {
		t.Fatal(err)
	}

	dsymm := make([]byte, 32)
	retval := DecryptSymmetricKey(esymm, key, dsymm)
	if !bytes.Equal(dsymm, retval) {
		t.Fatal("DecryptSymmetricKey does not return buffer correctly")
	}
	if !bytes.Equal(symm, dsymm) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestGeneralRead(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermissionFromPath([]string{"a", "b", "c"}, []uint16{2017, 12, 27, 04})
	if err != nil {
		t.Fatal(err)
	}

	prefixperm, err := ParsePermissionFromPath([]string{"a", "b", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	key, err := DelegateRaw(rand.Reader, master, prefixperm)
	if err != nil {
		t.Fatal(err)
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}

func TestBroadeningDelegation(t *testing.T) {
	hierarchy, master, err := CreateHierarchy(rand.Reader, "My Hierarchy")
	if err != nil {
		t.Fatal(err)
	}

	prefixperm, err := ParsePermissionFromPath([]string{"a", "b", "*"}, []uint16{2017, 12})
	if err != nil {
		t.Fatal(err)
	}

	perm, err := ParsePermissionFromPath([]string{"a", "b", "c"}, []uint16{2017, 12, 27, 04})
	if err != nil {
		t.Fatal(err)
	}

	intermediate, isecret := createEntityHelper(t, "Intermediate")
	reader, rsecret := createEntityHelper(t, "Reader")

	d1, err := DelegateBroadeningWithKey(rand.Reader, master, intermediate, perm)
	if err != nil {
		t.Fatal(err)
	}

	d2, err := DelegateBroadening(rand.Reader, hierarchy, isecret, reader, prefixperm)
	if err != nil {
		t.Fatal(err)
	}

	key := ResolveChain(d1, []*BroadeningDelegation{d2}, rsecret)
	if key == nil {
		t.Fatal("Could not resolve chain of delegations")
	}

	message := randomMessageHelper(t)

	emsg, err := Encrypt(rand.Reader, hierarchy, perm, message)
	if err != nil {
		t.Fatal(err)
	}

	decrypted := Decrypt(emsg, key)
	if !bytes.Equal(message, decrypted) {
		t.Fatal("Decrypted message is different from original message")
	}
}
