package csroaque_opt

import (
	"bytes"
	"crypto/rand"
	"io"
	"math/big"
	mRand "math/rand"
	"testing"
	"time"

	"github.com/ucbrise/starwave/crypto/oaque"
	"vuvuzela.io/crypto/bn256"
)

const attrMaxSize, userMaxSize = 10, 10

func NewMessage() *bn256.GT {
	return bn256.Pair(new(bn256.G1).ScalarBaseMult(big.NewInt(3)), new(bn256.G2).ScalarBaseMult(big.NewInt(5)))
}

func encryptHelper(t *testing.T, params *Params, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) *Cipher {
	cipher, err := Encrypt(params, attrs, revoc, message)
	if err != nil {
		t.Fatal(err)
	}
	return cipher
}

func genFromMasterHelper(t *testing.T, params *Params, masterkey *MasterKey, attrs oaque.AttributeList, userNum int, newUser int) *PrivateKey {
	// Generate key for the single attributes
	key, err := KeyGen(params, masterkey, attrs, userNum, newUser)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func qualifyHelper(t *testing.T, params *Params, key *PrivateKey, attrs oaque.AttributeList, lEnd int, rEnd int) *PrivateKey {
	key, err := QualifyKey(params, key, attrs, lEnd, rEnd)
	if err != nil {
		t.Fatal(err)
	}
	return key
}

func decryptAndCheckHelper(t *testing.T, params *Params, key *PrivateKey, cipher *Cipher, message *bn256.GT) {
	decrypted := Decrypt(params, key, cipher)
	if decrypted == nil || !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		t.Fatal("Original and decrypted messages differ")
	}
}

func decryptAndCheckHelper2(t *testing.T, params *Params, key *PrivateKey, cipher *Cipher, message *bn256.GT) {
	decrypted := Decrypt(params, key, cipher)
	if decrypted == nil || !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
		return
	}
	t.Fatal("Original and decrypted messages are the same")
}

func attributeFromMasterHelper(t *testing.T, attrs oaque.AttributeList, revoc RevocationList) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs, revoc, message)

	// Generate key for the single attributes
	key := genFromMasterHelper(t, params, masterkey, attrs, 0, userMaxSize)

	decryptAndCheckHelper(t, params, key, ciphertext, message)
}

func TestSingleAttribute(t *testing.T) {
	attributeFromMasterHelper(t, oaque.AttributeList{0: big.NewInt(0)}, nil)
}

func TestSingleSparseAttribute(t *testing.T) {
	attributeFromMasterHelper(t, oaque.AttributeList{1: big.NewInt(0)}, nil)
}

func TestMultipleSparseAttributes(t *testing.T) {
	attributeFromMasterHelper(t, oaque.AttributeList{1: big.NewInt(0), attrMaxSize - 1: big.NewInt(123)}, nil)
}

func TestQualifyKey(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{1, 2, 4}
	revoc2 := RevocationList{1, 2, 3}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)
	ciphertext2 := encryptHelper(t, params, attrs2, revoc2, message)

	// Generate key in two steps
	//println(userMaxSize)
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 0, 4)
	key2 := qualifyHelper(t, params, key1, attrs2, *key1.lEnd, *key1.lEnd+2)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
	decryptAndCheckHelper2(t, params, key2, ciphertext2, message)
}

func TestQualifyKey2(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{1, 2, 3, 7, 8}
	revoc2 := RevocationList{1, 2, 3, 7, 8, 9}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)
	ciphertext2 := encryptHelper(t, params, attrs2, revoc2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 0, 9)
	key2 := qualifyHelper(t, params, key1, attrs2, 7, 9)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
	decryptAndCheckHelper2(t, params, key2, ciphertext2, message)
}

func TestQualifyKey3(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{1, 5}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 0, 9)
	key2 := qualifyHelper(t, params, key1, attrs2, 8, 8)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
}

func TestQualifyKey4(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{1, 2, 4, 5, 6}
	revoc2 := RevocationList{1, 2, 3, 4, 5, 6}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)
	ciphertext2 := encryptHelper(t, params, attrs2, revoc2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 2, 4)
	key2 := qualifyHelper(t, params, key1, attrs2, 3, 4)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
	decryptAndCheckHelper2(t, params, key2, ciphertext2, message)
}

func TestQualifyKey5(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{5, 6}
	revoc2 := RevocationList{4, 5, 6}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)
	ciphertext2 := encryptHelper(t, params, attrs2, revoc2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 2, 4)
	key2 := qualifyHelper(t, params, key1, attrs2, 4, 6)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
	decryptAndCheckHelper2(t, params, key2, ciphertext2, message)
}

func TestQualifyKey6(t *testing.T) {
	// Set up parameters
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := oaque.AttributeList{2: big.NewInt(4)}
	attrs2 := oaque.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	revoc1 := RevocationList{3, 4}
	revoc2 := RevocationList{3, 4, 5}

	// Come up with a message to encrypt
	message := NewMessage()

	// Encrypt a message under the top level public key
	ciphertext := encryptHelper(t, params, attrs2, revoc1, message)
	ciphertext2 := encryptHelper(t, params, attrs2, revoc2, message)

	// Generate key in two steps
	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 2, 4)
	key2 := qualifyHelper(t, params, key1, attrs2, 3, 5)

	//	decryptAndCheckHelper(t, params, key1, ciphertext, message)
	decryptAndCheckHelper(t, params, key2, ciphertext, message)
	decryptAndCheckHelper2(t, params, key2, ciphertext2, message)
}

func NewRandomMessage(random io.Reader) (*bn256.GT, error) {
	_, g1, err := bn256.RandomG1(random)
	if err != nil {
		return nil, err
	}
	_, g2, err := bn256.RandomG2(random)
	if err != nil {
		return nil, err
	}
	return bn256.Pair(g1, g2), nil
}

// The maximum number of leaves in the tree is 2000

const maxLeaves int = 65536

func BenchmarkSetup(b *testing.B) {
	for i := 0; i < b.N; i++ {
		_, _, err := Setup(rand.Reader, 20, maxLeaves)
		if err != nil {
			b.Fatal(err)
		}
	}
}

func QualifyKeyBenchmarkHelper(b *testing.B, numAttributes int, numLeaves int) {
	b.StopTimer()
	mRand.Seed(time.Now().UTC().UnixNano())

	for i := 0; i < b.N; i++ {
		// Set up parameters
		params, master, err := Setup(rand.Reader, 20, maxLeaves)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(oaque.AttributeList)
		for i := 0; i != numAttributes-1; i++ {
			attrs[oaque.AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		key, err := KeyGen(params, master, oaque.AttributeList{0: attrs[0]}, 0, maxLeaves)
		if err != nil {
			b.Fatal(err)
		}

		lEnd := 1 + mRand.Intn(maxLeaves-numLeaves)
		rEnd := lEnd + numLeaves

		if rEnd > maxLeaves {
			b.Fatal("out of bound")
		}

		b.StartTimer()
		_, err = QualifyKey(params, key, attrs, lEnd, rEnd)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

// The first parameter is the number of attribute of the final key. The second
// parameter is the number of leaves of the final key.

func BenchmarkQualifyKey_a20_l5(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 5)
}

func BenchmarkQualifyKey_a20_l10(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 10)
}

func BenchmarkQualifyKey_a20_l20(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 20)
}

func BenchmarkQualifyKey_a20_l30(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 30)
}

func BenchmarkQualifyKey_a20_l40(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 40)
}

func BenchmarkQualifyKey_a20_l50(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 50)
}

func BenchmarkQualifyKey_a20_l60(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 60)
}

func BenchmarkQualifyKey_a20_l70(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 70)
}

func BenchmarkQualifyKey_a20_l80(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 80)
}

func BenchmarkQualifyKey_a20_l90(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 90)
}

func BenchmarkQualifyKey_a20_l100(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 100)
}

func BenchmarkQualifyKey_a20_l1000(b *testing.B) {
	QualifyKeyBenchmarkHelper(b, 20, 1000)
}

//==============================================================================

func EncryptBenchmarkHelperForLeaves(b *testing.B, numAttributes int, numRevocations int) {
	b.StopTimer()

	// Set up parameters
	params, _, err := Setup(rand.Reader, 20, maxLeaves)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		//println(i, b.N)
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(oaque.AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[oaque.AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		perms := make(RevocationList, 0, maxLeaves)
		for i := 0; i != maxLeaves; i++ {
			perms = append(perms, i+1)
		}

		for i := range perms {
			j, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(i+1)))
			if err != nil {
				b.Fatal(err)
			}

			perms[i], perms[j.Uint64()] = perms[j.Uint64()], perms[i]
		}

		revocs := make(RevocationList, 0, numRevocations)
		for i := 0; i != numRevocations; i++ {
			revocs = append(revocs, perms[i])
		}

		b.StartTimer()
		_, err = Encrypt(params, attrs, revocs, message)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

// Assume there are at most 2000 leaves. The first parameter is the number of slots
// for attributes (which does not include slots for CS Method). The second parameter
// is the number of revoked leaves.

func BenchmarkEncryptForLeaves_5_0(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 5, 0)
}

func BenchmarkEncryptForLeaves_10_0(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 10, 0)
}

func BenchmarkEncryptForLeaves_15_0(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 15, 0)
}

func BenchmarkEncryptForLeaves_20_0(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 20, 0)
}

func BenchmarkEncryptForLeaves_5_50(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 5, 50)
}

func BenchmarkEncrypForLeaves_10_50(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 10, 50)
}

func BenchmarkEncryptForLeaves_15_50(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 15, 50)
}

func BenchmarkEncryptForLeaves_20_50(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 20, 50)
}

func BenchmarkEncryptForLeaves_5_500(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 5, 500)
}

func BenchmarkEncryptForLeaves_10_500(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 10, 500)
}

func BenchmarkEncryptForLeaves_15_500(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 15, 500)
}

func BenchmarkEncryptForLeaves_20_500(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 20, 500)
}

func BenchmarkEncryptForLeaves_5_1000(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 5, 1000)
}

func BenchmarkEncryptForLeaves_10_1000(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 10, 1000)
}

func BenchmarkEncryptForLeaves_15_1000(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 15, 1000)
}

func BenchmarkEncryptForLeaves_20_1000(b *testing.B) {
	EncryptBenchmarkHelperForLeaves(b, 20, 1000)
}

//======================================================================

func DecryptBenchmarkHelperForLeaves(b *testing.B, numAttributes int, numRevocations int, numPermissions int) {
	b.StopTimer()

	// Set up parameters
	params, master, err := Setup(rand.Reader, 20, maxLeaves)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(oaque.AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[oaque.AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		perms := make(RevocationList, 0, maxLeaves)
		for i := 0; i != maxLeaves; i++ {
			perms = append(perms, i+1)
		}

		for i := range perms {
			j, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(i+1)))
			if err != nil {
				b.Fatal(err)
			}

			perms[i], perms[j.Uint64()] = perms[j.Uint64()], perms[i]
		}

		revocs := make(RevocationList, 0, numRevocations)
		for i := 0; i != numRevocations; i++ {
			revocs = append(revocs, perms[i])
		}

		begin, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(*params.userSize-numPermissions+1)))
		if err != nil {
			b.Fatal(err)
		}

		key, err := KeyGen(params, master, attrs, (int)(begin.Uint64()), numPermissions)
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(params, attrs, revocs, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		//	println(time.Now().Second())
		decrypted := Decrypt(params, key, ciphertext)
		//println(time.Now().Second())
		//oaque.Decrypt(key.root.keyList[0].key, ciphertext.cipherlist[0].ciphertext)
		//println(time.Now().Second())
		//println(b.N, i)
		b.StopTimer()

		cnt := 0
		for i := range revocs {
			if revocs[i] > (int)(begin.Uint64()) && revocs[i] <= (int)(begin.Uint64())+numPermissions {
				cnt++
			}
		}

		flag := (cnt < numPermissions)

		if flag {
			if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
				b.Fatal("Original and decrypted messages differ")
			}
		} else {
			if bytes.Equal(message.Marshal(), decrypted.Marshal()) {
				b.Fatal("Original and decrypted messages are the same")
			}
		}
	}
}

// Assume there are at most 65536 leaves. The first parameter is the number of slots
// for attributes (which does not include slots for CS Method). The second parameter
// is the number of revoked leaves. The third parameter is the number of leaves the user has.

func BenchmarkDecryptForLeaves_a5_r0_n50(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 5, 0, 50)
}

func BenchmarkDecryptForLeaves_a10_r0_n50(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 10, 0, 50)
}

func BenchmarkDecryptForLeaves_a15_r0_n50(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 15, 0, 50)
}

func BenchmarkDecrypForLeavest_a20_r0_n50(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 20, 0, 50)
}

func BenchmarkDecryptForLeaves_r50_n50_a5(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 5, 50, 50)
}

func BenchmarkDecryptForLeaves_r50_n50_a10(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 10, 50, 50)
}

func BenchmarkDecryptForLeaves_r50_n50_a15(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 15, 50, 50)
}

func BenchmarkDecryptForLeaves_r50_n50_a20(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 20, 50, 50)
}

func BenchmarkDecryptForLeaves_r500_n200_a5(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 5, 500, 200)
}

func BenchmarkDecryptForLeaves_r500_n200_a10(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 10, 500, 200)
}

func BenchmarkDecryptForLeaves_r500_n200_a15(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 15, 500, 200)
}

func BenchmarkDecryptForLeaves_r500_n200_a20(b *testing.B) {
	DecryptBenchmarkHelperForLeaves(b, 20, 500, 200)
}

//=============================================================================

type interval struct {
	lEnd int
	rEnd int
}

//const totUsers int = 200

func EncryptBenchmarkHelperForUsers(b *testing.B, numAttributes int, numRevocations int, totUsers int) {
	b.StopTimer()

	keyLen := maxLeaves / totUsers
	// Set up parameters
	params, _, err := Setup(rand.Reader, 20, maxLeaves)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		//println(i, b.N)
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(oaque.AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[oaque.AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		perms := make([]*interval, totUsers)
		for i, j := 0, 0; i != totUsers; i++ {
			tmp := &interval{lEnd: j + 1, rEnd: j + keyLen}
			perms[i] = tmp
			j = j + keyLen
		}

		for i := range perms {
			j, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(i+1)))
			if err != nil {
				b.Fatal(err)
			}
			perms[i], perms[j.Uint64()] = perms[j.Uint64()], perms[i]
		}

		revocs := make(RevocationList, 0, numRevocations*keyLen)
		for i := 0; i != numRevocations; i++ {
			for j := perms[i].lEnd; j <= perms[i].rEnd; j++ {
				revocs = append(revocs, j)
			}
		}

		b.StartTimer()
		_, err = Encrypt(params, attrs, revocs, message)
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

// Assume there are at most 65536 leaves.
// The first parameter is the number of slots for attributes (which does not
// include slots for CS Method). The second parameter is the number of revoked leaves,
// The third parameter is the number of users, and each user owns 65536/totUsers leaves.

func BenchmarkEncryptForUsers_20_0_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 0, 256)
}

func BenchmarkEncryptForUsers_20_5_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 5, 256)
}

func BenchmarkEncryptForUsers_20_10_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 10, 256)
}

func BenchmarkEncryptForUsers_20_20_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 20, 256)
}

func BenchmarkEncryptForUsers_20_30_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 30, 256)
}

func BenchmarkEncryptForUsers_20_40_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 40, 256)
}

func BenchmarkEncryptForUsers_20_50_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 50, 256)
}

func BenchmarkEncryptForUsers_20_60_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 60, 256)
}

func BenchmarkEncryptForUsers_20_70_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 70, 256)
}

func BenchmarkEncryptForUsers_20_80_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 80, 256)
}

func BenchmarkEncryptForUsers_20_90_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 90, 256)
}

func BenchmarkEncryptForUsers_20_100_256(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 100, 256)
}

func BenchmarkEncryptForUsers_20_512_1024(b *testing.B) {
	EncryptBenchmarkHelperForUsers(b, 20, 512, 1024)
}

//==============================================================================

func DecryptBenchmarkHelperForUsers(b *testing.B, numAttributes int, numRevocations int, totUsers int) {
	b.StopTimer()

	keyLen := maxLeaves / totUsers
	// Set up parameters
	params, master, err := Setup(rand.Reader, 20, maxLeaves)
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		//println(i)
		message, err := NewRandomMessage(rand.Reader)
		if err != nil {
			b.Fatal(err)
		}

		attrs := make(oaque.AttributeList)
		for i := 0; i != numAttributes; i++ {
			attrs[oaque.AttributeIndex(i)], err = rand.Int(rand.Reader, bn256.Order)
			if err != nil {
				b.Fatal(err)
			}
		}

		perms := make([]*interval, totUsers)
		for i, j := 0, 0; i != totUsers; i++ {
			tmp := &interval{lEnd: j + 1, rEnd: j + keyLen}
			perms[i] = tmp
			j = j + keyLen
		}

		for i := range perms {
			j, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(i+1)))
			if err != nil {
				b.Fatal(err)
			}
			perms[i], perms[j.Uint64()] = perms[j.Uint64()], perms[i]
		}

		revocs := make(RevocationList, 0, numRevocations*keyLen)
		for i := 0; i != numRevocations; i++ {
			for j := perms[i].lEnd; j <= perms[i].rEnd; j++ {
				revocs = append(revocs, j)
			}
		}

		lEnd := perms[numRevocations].lEnd
		rEnd := perms[numRevocations].rEnd

		key, err := KeyGen(params, master, attrs, lEnd-1, rEnd-lEnd+1)
		if err != nil {
			b.Fatal(err)
		}

		ciphertext, err := Encrypt(params, attrs, revocs, message)
		if err != nil {
			b.Fatal(err)
		}

		b.StartTimer()
		decrypted := Decrypt(params, key, ciphertext)
		b.StopTimer()

		if !bytes.Equal(message.Marshal(), decrypted.Marshal()) {
			b.Fatal("Original and decrypted messages differ")
		}
	}
}

// Assume there are at most 2000 leaves, 200 users, and each user owns 10 leaves.
// The first parameter is the number of slots for attributes (which does not
// include slots for CS Method). The second parameter is the number of revoked leaves.

func BenchmarkDecryptForUsers_a20_r0(b *testing.B) {
	//	DecryptBenchmarkHelperForUsers(b, 20, 0)
}

func BenchmarkDecryptForUsers_a20_r5(b *testing.B) {
	//	DecryptBenchmarkHelperForUsers(b, 20, 5)
}

func BenchmarkDecryptForUsers_a20_r20(b *testing.B) {
	//	DecryptBenchmarkHelperForUsers(b, 20, 20)
}

func BenchmarkDecryptForUsers_a20_r50(b *testing.B) {
	//	DecryptBenchmarkHelperForUsers(b, 20, 50)
}

func BenchmarkDecryptForUsers_a20_r100(b *testing.B) {
	//	DecryptBenchmarkHelperForUsers(b, 20, 100)
}
