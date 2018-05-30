package csroaque_opt

import (
	"io"
	"math"
	"math/big"
	"strconv"

	"github.com/ucbrise/starwave/crypto/oaque"
	"vuvuzela.io/crypto/bn256"
)

type Params struct {
	userSize   *int
	userHeight *int
	params     *oaque.Params
}

type MasterKey struct {
	masterKey *oaque.MasterKey
}

type privateKeyNode struct {
	left       *privateKeyNode
	right      *privateKeyNode
	delegable  *bool
	privateKey *oaque.PrivateKey
}

//	PrivateKey is a subtree in BEtree(note that this subtree might not be a Complete Binary Tree)
type PrivateKey struct {
	root       *privateKeyNode
	lEnd, rEnd *int
}

func (p *PrivateKey) GetLEnd() int {
	return *p.lEnd
}

func (p *PrivateKey) GetREnd() int {
	return *p.rEnd
}

type RevocationList []int

type Ciphertext struct {
	ciphertext *oaque.Ciphertext
	lEnd, rEnd *int
}

func (p *Ciphertext) GetLEnd() int {
	return *p.lEnd
}

func (p *Ciphertext) GetREnd() int {
	return *p.rEnd
}

type CiphertextList []*Ciphertext

type Cipher struct {
	cipherlist CiphertextList
	// TODO: attrs in cipher or in private key
	attrs oaque.AttributeList
}

func (c *Cipher) GetCipherlist() *CiphertextList {
	return &c.cipherlist
}

func (c *Cipher) SetAttrs(attrs *oaque.AttributeList) {
	c.attrs = *attrs
}

// geSize is the base size in bytes of a marshalled group element. The size of
// a marshalled element of G2 is geSize. The size of a marshalled element of G1
// is 2 * geSize. The size of a marshalled element of GT is 6 * geSize.
const geSize = 64

// geShift is the base shift for a marshalled group element
const geShift = 6

// attributeIndexSize is the size, in bytes, of an attribute index
const attributeIndexSize = 1

func geIndex(encoded []byte, index int, len int) []byte {
	return encoded[index<<geShift : (index+len)<<geShift]
}

// CiphertextMarshalledSize is the size of a marshalled ciphertext, in bytes.
const CiphertextMarshalledSize = 9 << geShift

func (c *Cipher) Marshal() []byte {
	marshalled := make([]byte, 0)

	/*for _, att := range c.attrs {
		tmp, err := att.MarshalText()
		if err != nil {
			panic("Marshal failed")
		}
		tmpString := string(tmp) + "$"

		marshalled = append(marshalled, []byte(tmpString)...)
	}*/

	//tmpString := "&"
	//marshalled = append(marshalled, []byte(tmpString)...)
	//println(len(marshalled))

	for i := 0; i < len(c.cipherlist); i++ {
		tmp := c.cipherlist[i].ciphertext.Marshal()
		//copy(marshalled[tot:tot+l], tmp)
		marshalled = append(marshalled, tmp...)

		/*{
			// Debug
			cc := &Ciphertext{}
			cc.ciphertext = &oaque.Ciphertext{}
			println(tot - l)
			println(tot)
			ck := cc.ciphertext.Unmarshal(marshalled[tot-l : tot])
			if !ck {
				//println(string(marshalled[cnt : cnt+CiphertextMarshalledSize+5]))
				panic("haha")
			}
		}*/

		{
			tmpL := *c.cipherlist[i].lEnd
			tmpString := strconv.FormatUint(uint64(tmpL), 10) + "$"
			//copy(marshalled[tot:tot+l], tmpString)
			marshalled = append(marshalled, tmpString...)
		}

		{
			tmpR := *c.cipherlist[i].rEnd
			tmpString := strconv.FormatUint(uint64(tmpR), 10) + "$"
			//copy(marshalled[tot:tot+l], tmpString)
			marshalled = append(marshalled, tmpString...)
		}
	}

	marshalled = append(marshalled, '&')
	println("haha")
	println(len(marshalled))
	return marshalled
}

func (c *Cipher) UnMarshal(marshalled []byte) bool {
	c.cipherlist = make(CiphertextList, 0)
	cnt := 0

	/*c.attrs = make(oaque.AttributeList)
	for idx := 0; marshalled[cnt] != '&'; {
		op := cnt
		for marshalled[cnt] != '$' {
			cnt++
		}
		tmp := big.NewInt(0)
		tmp.UnmarshalText(marshalled[op:cnt])
		c.attrs[oaque.AttributeIndex(idx)] = tmp
		idx++
		cnt++
	}
	cnt++*/

	for cnt < len(marshalled) && marshalled[cnt] != '&' {
		//		println("----")
		//		println(cnt)
		//		println(cnt + CiphertextMarshalledSize)
		//		println(len(marshalled))
		tmp := &Ciphertext{}
		tmp.ciphertext = &oaque.Ciphertext{}
		ck := tmp.ciphertext.Unmarshal(marshalled[cnt : cnt+CiphertextMarshalledSize])
		if !ck {
			//println(string(marshalled[cnt : cnt+CiphertextMarshalledSize+5]))
			println("UnMarshal for ciphertext failed")
			return false
		}
		cnt += CiphertextMarshalledSize

		op := cnt
		for marshalled[cnt] != '$' {
			cnt++
		}
		p1, err := strconv.ParseUint(string(marshalled[op:cnt]), 10, 64)
		if err != nil {
			println("UnMarshal for lEnd failed")
			return false
		}
		p2 := int(p1)
		tmp.lEnd = &p2
		cnt++

		op = cnt
		for marshalled[cnt] != '$' {
			cnt++
		}
		p1, err = strconv.ParseUint(string(marshalled[op:cnt]), 10, 64)
		if err != nil {
			println("UnMarshal for rEnd failed")
			return false
		}
		p2 = int(p1)
		tmp.rEnd = &p2
		cnt++

		c.cipherlist = append(c.cipherlist, tmp)
	}

	return true
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 0 to l-1). The parameter	"n" is the total number of users
// supported(indexed from 1 to n).
func Setup(random io.Reader, l int, n int) (*Params, *MasterKey, error) {
	params := &Params{}
	masterKey := &MasterKey{}
	var err error

	params.userSize, params.userHeight = new(int), new(int)
	*params.userSize = n
	*params.userHeight = int(math.Ceil(math.Log2(float64(n))))

	//	masterKey.userNumber = new(int)
	//	*masterKey.userNumber = n

	params.params, masterKey.masterKey, err = oaque.Setup(random, *params.userHeight+l, false)
	if err != nil {
		return nil, nil, err
	}

	//	params.revocationList = make([]int, 0, n)

	return params, masterKey, nil
}

// Return a new AttributeList containing original attrs and position of node vi in
// the tree.
func newAttributeList(params *Params, nodeID []int, attrs oaque.AttributeList, depth int, delegable bool) oaque.AttributeList {

	// NOTE: Assume attributeIndex is int
	newAttr := make(oaque.AttributeList)
	for index := range attrs {
		newAttr[oaque.AttributeIndex(*params.userHeight+int(index))] = attrs[index]
	}

	//TODO: Add hash function here or inside oaque
	for i := 0; i < depth; i++ {
		newAttr[oaque.AttributeIndex(i)] = big.NewInt(int64(nodeID[i]))
	}

	if !delegable {
		for i := depth; i < *params.userHeight; i++ {
			newAttr[oaque.AttributeIndex(i)] = nil
		}
	}
	return newAttr
}

func treeKeyGen(params *Params, master *MasterKey, left int, right int, lEnd int, rEnd int, attrs oaque.AttributeList, nodeID []int, depth int) (*privateKeyNode, error) {
	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	var err error
	node := &privateKeyNode{}

	//	This private key should be delegable
	if lEnd <= left && right <= rEnd {
		newAttrs := newAttributeList(params, nodeID, attrs, depth, true)
		node.privateKey, err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)

		if err != nil {
			return nil, err
		}

		node.delegable = new(bool)
		node.left, node.right, *node.delegable = nil, nil, true
		return node, nil
	}

	// This private key should not be delegable
	newAttrs := newAttributeList(params, nodeID, attrs, depth, false)
	node.privateKey, err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)
	if err != nil {
		return nil, err
	}

	mid := (left + right) / 2 // Note: it should be div

	nodeID[depth] = 0
	node.left, err = treeKeyGen(params, master, left, mid, lEnd, rEnd, attrs, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	node.right, err = treeKeyGen(params, master, mid+1, right, lEnd, rEnd, attrs, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	node.delegable = new(bool)
	*node.delegable = false
	//nodeID[depth] = nil
	return node, err
}

// KeyGen generates a key for an attribute list using the master key.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. userNum is the number of current users in the system,
// and newUser is number of privateKey which namespace wants to generate.

func KeyGen(params *Params, master *MasterKey, attrs oaque.AttributeList, userNum int, newUser int) (*PrivateKey, error) {
	if newUser <= 0 || userNum < 0 || userNum+newUser > *params.userSize {
		panic("Parameters for KeyGen are out of bound")
	}
	key := &PrivateKey{}
	lEnd, rEnd := userNum+1, userNum+newUser
	var err error
	nodeID := make([]int, *params.userHeight, *params.userHeight)

	key.root, err = treeKeyGen(params, master, 1, *params.userSize, lEnd, rEnd, attrs, nodeID, 0)
	if err != nil {
		return nil, err
	}

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd, *key.rEnd = lEnd, rEnd
	return key, nil
}

func treeQualifyKey(params *Params, qNode *privateKeyNode, left int, right int, lEnd int, rEnd int, attrs oaque.AttributeList, nodeID []int, depth int) (*privateKeyNode, error) {
	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	if qNode == nil {
		return nil, nil
	}

	var err error
	node := &privateKeyNode{}

	if lEnd <= left && right <= rEnd {
		newAttrs := newAttributeList(params, nodeID, attrs, depth, true)
		node.privateKey, err = oaque.QualifyKey(nil, params.params, qNode.privateKey, newAttrs)
		if err != nil {
			return nil, err
		}

		node.delegable = new(bool)
		node.left, node.right, *node.delegable = nil, nil, true
		return node, nil
	}

	newAttrs := newAttributeList(params, nodeID, attrs, depth, false)
	node.privateKey, err = oaque.QualifyKey(nil, params.params, qNode.privateKey, newAttrs)
	if err != nil {
		return nil, err
	}

	mid := (left + right) / 2 // Note: it should be div

	nodeID[depth] = 0
	node.left, err = treeQualifyKey(params, qNode.left, left, mid, lEnd, rEnd, attrs, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	node.right, err = treeQualifyKey(params, qNode.right, mid+1, right, lEnd, rEnd, attrs, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	node.delegable = new(bool)
	*node.delegable = false
	//	nodeID[depth] = nil
	return node, err
}

// QualifyKey uses a key to generate a new key with restricted permissions, by
// adding the the specified attributes. Remember that adding new attributes
// restricts the permissions. Furthermore, attributes are immutable once set,
// so the attrs map must contain mappings for attributes that are already set.
// The attrs argument is a mapping from attribute to its value; attributes
// not in the map are not set. lEnd and rEnd specify the leafID range to be delegated
func QualifyKey(params *Params, qualify *PrivateKey, attrs oaque.AttributeList, lEnd int, rEnd int) (*PrivateKey, error) {
	if !(*qualify.lEnd <= lEnd && rEnd <= *qualify.rEnd) {
		panic("Cannot generate key out bound of given key")
	}

	key := &PrivateKey{}
	var err error

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd = lEnd
	*key.rEnd = rEnd

	nodeID := make([]int, *params.userHeight, *params.userHeight)

	key.root, err = treeQualifyKey(params, qualify.root, 1, *params.userSize, lEnd, rEnd, attrs, nodeID, 0)
	if err != nil {
		return nil, err
	}
	return key, nil
}

func treeEncrypt(params *Params, left int, right int, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT, nodeID []int, depth int) (CiphertextList, error) {
	if left > right {
		return nil, nil
	}

	flag := false
	// This check can be reduced to O(log r), if we build segment tree on top of RevocationList
	for i := range revoc {
		if left <= revoc[i] && revoc[i] <= right {
			flag = true
			break
		}
	}

	if !flag {
		var cipher CiphertextList
		cipher = make(CiphertextList, 1, 1)
		cipher[0] = new(Ciphertext)
		var err error
		newAttrs := newAttributeList(params, nodeID, attrs, depth, true)

		cipher[0].ciphertext, err = oaque.Encrypt(nil, params.params, newAttrs, message)
		if err != nil {
			return nil, err
		}
		cipher[0].lEnd, cipher[0].rEnd = new(int), new(int)
		*cipher[0].lEnd, *cipher[0].rEnd = left, right

		return cipher, nil
	}

	if left == right {
		return nil, nil
	}

	var err error
	var cipherLeft, cipherRight CiphertextList
	mid := (left + right) / 2 // note should be div

	nodeID[depth] = 0
	cipherLeft, err = treeEncrypt(params, left, mid, attrs, revoc, message, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	cipherRight, err = treeEncrypt(params, mid+1, right, attrs, revoc, message, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	cipher := make(CiphertextList, 0, len(cipherLeft)+len(cipherRight))
	cipher = append(cipher, cipherLeft...)
	cipher = append(cipher, cipherRight...)

	return cipher, nil
}

// No function for revocation, since this is a stateless revocation scheme. User
// only need to specify revocation list along with URI during encryption.

// Encrypt first find a node set which cover all the unrevoked leaves, and then
// encrypts message under those nodes' keys. The set covering algorithm used here
// is Complete Tree(CS)
func Encrypt(params *Params, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) (*Cipher, error) {
	cipher := &Cipher{}
	var err error
	nodeID := make([]int, *params.userHeight, *params.userHeight)

	cipher.cipherlist, err = treeEncrypt(params, 1, *params.userSize, attrs, revoc, message, nodeID, 0)
	if err != nil {
		return nil, err
	}

	cipher.attrs = make(oaque.AttributeList)
	for index := range attrs {
		cipher.attrs[index] = attrs[index]
	}

	return cipher, nil
}

func newNodeID(params *Params, left int, right int, lEnd int, rEnd int, nodeID []int, depth int) (int, error) {
	var mid int
	for i := depth; i < *params.userHeight; i++ {
		if left == lEnd && right == rEnd {
			return i, nil
		}
		mid = (left + right) / 2
		if rEnd <= mid {
			nodeID[i] = 0
			right = mid
		} else if mid+1 <= lEnd {
			nodeID[i] = 1
			left = mid + 1
		} else {
			panic("Cannot find valid node ID for given interval")
		}
	}
	if left == lEnd && right == rEnd {
		return *params.userHeight, nil
	}
	panic("Node depth is out of range")
}

func treeDecrypt(params *Params, pNode *privateKeyNode, left int, right int, cipher *Cipher, nodeID []int, depth int) *bn256.GT {
	if left > right {
		return nil
	}

	if pNode == nil {
		return nil
	}

	if *pNode.delegable {
		for i := range cipher.cipherlist {
			if left <= *cipher.cipherlist[i].lEnd && *cipher.cipherlist[i].rEnd <= right {
				var err error
				newDepth, err := newNodeID(params, left, right, *cipher.cipherlist[i].lEnd, *cipher.cipherlist[i].rEnd, nodeID, depth)
				if err != nil {
					return nil
				}

				newAttrs := newAttributeList(params, nodeID, cipher.attrs, newDepth, true)

				tmpPrivateKey := oaque.NonDelegableKey(params.params, pNode.privateKey, newAttrs)

				plaintext := oaque.Decrypt(tmpPrivateKey, cipher.cipherlist[i].ciphertext)
				return plaintext
			}
		}
		return nil
	}

	for i := range cipher.cipherlist {
		if left == *cipher.cipherlist[i].lEnd && right == *cipher.cipherlist[i].rEnd {
			newAttrs := newAttributeList(params, nodeID, cipher.attrs, depth, true)

			tmpPrivateKey := oaque.NonDelegableKey(params.params, pNode.privateKey, newAttrs)

			plaintext := oaque.Decrypt(tmpPrivateKey, cipher.cipherlist[i].ciphertext)
			return plaintext
		}
	}

	var plaintext *bn256.GT
	mid := (left + right) / 2

	nodeID[depth] = 0
	plaintext = treeDecrypt(params, pNode.left, left, mid, cipher, nodeID, depth+1)
	if plaintext != nil {
		return plaintext
	}

	nodeID[depth] = 1
	plaintext = treeDecrypt(params, pNode.right, mid+1, right, cipher, nodeID, depth+1)
	if plaintext != nil {
		return plaintext
	}

	return nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(params *Params, key *PrivateKey, cipher *Cipher) *bn256.GT {
	nodeID := make([]int, *params.userHeight, *params.userHeight)
	plaintext := treeDecrypt(params, key.root, 1, *params.userSize, cipher, nodeID, 0)
	return plaintext
}
