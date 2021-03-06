package csroaque_opt

import (
	"encoding/binary"
	"fmt"
	"io"
	"math"

	"github.com/samkumar/embedded-pairing/lang/go/cryptutils"
	"github.com/samkumar/embedded-pairing/lang/go/wkdibe"
)

type Params struct {
	userSize   *int
	userHeight *int
	params     *wkdibe.Params
}

type MasterKey struct {
	masterKey *wkdibe.MasterKey
}

type privateKeyNode struct {
	left       *privateKeyNode
	right      *privateKeyNode
	delegable  *bool
	privateKey *wkdibe.SecretKey
}

//	PrivateKey is a subtree in BEtree(note that this subtree might not be a Complete Binary Tree)
type PrivateKey struct {
	root       *privateKeyNode
	lEnd, rEnd *int
}

func treeCountNodes(pNode *privateKeyNode) (int, int) {
	if pNode == nil {
		return 0, 0
	}
	cnt_nd, cnt_d := 0, 0
	if *pNode.delegable {
		cnt_d++
	} else {
		cnt_nd++
	}

	tmp_nd, tmp_d := treeCountNodes(pNode.left)
	cnt_nd, cnt_d = cnt_nd+tmp_nd, cnt_d+tmp_d

	tmp_nd, tmp_d = treeCountNodes(pNode.right)
	cnt_nd, cnt_d = cnt_nd+tmp_nd, cnt_d+tmp_d
	return cnt_nd, cnt_d
}

func (p *PrivateKey) CountNodes() {
	cnt_nd, cnt_d := treeCountNodes(p.root)
	fmt.Printf("The number of non-delegable keys is %d\n", cnt_nd)
	fmt.Printf("The number of delegable keys is %d\n", cnt_d)
}

func (p *PrivateKey) GetLEnd() int {
	return *p.lEnd
}

func (p *PrivateKey) GetREnd() int {
	return *p.rEnd
}

type RevocationList []int

type Ciphertext struct {
	ciphertext *wkdibe.Ciphertext
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
	attrs wkdibe.AttributeList
}

func (c *Cipher) GetCipherlist() *CiphertextList {
	return &c.cipherlist
}

func (c *Cipher) SetAttrs(attrs *wkdibe.AttributeList) {
	c.attrs = *attrs
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 0 to l-1). The parameter	"n" is the total number of users
// supported(indexed from 1 to n).
func Setup(random io.Reader, l int, n int) (*Params, *MasterKey, error) {
	params := &Params{}
	masterKey := &MasterKey{}

	params.userSize, params.userHeight = new(int), new(int)
	*params.userSize = n
	*params.userHeight = int(math.Ceil(math.Log2(float64(n))))

	//	masterKey.userNumber = new(int)
	//	*masterKey.userNumber = n

	params.params, masterKey.masterKey = wkdibe.Setup(*params.userHeight+l, false)

	//	params.revocationList = make([]int, 0, n)

	return params, masterKey, nil
}

// Return a new AttributeList containing original attrs and position of node vi in
// the tree.
func newAttributeList(params *Params, nodeID []int, attrs wkdibe.AttributeList, depth int, delegable bool) wkdibe.AttributeList {

	// NOTE: Assume attributeIndex is int
	newAttr := make(wkdibe.AttributeList)
	for index := range attrs {
		newAttr[wkdibe.AttributeIndex(*params.userHeight+int(index))] = attrs[index]
	}

	for i := 0; i < depth; i++ {
		buffer := make([]byte, 8)
		binary.LittleEndian.PutUint64(buffer, uint64(nodeID[i]))
		newAttr[wkdibe.AttributeIndex(i)] = cryptutils.HashToZp(buffer)
	}

	if !delegable {
		for i := depth; i < *params.userHeight; i++ {
			newAttr[wkdibe.AttributeIndex(i)] = nil
		}
	}
	return newAttr
}

func treeKeyGen(params *Params, master *MasterKey, left int, right int, lEnd int, rEnd int, attrs wkdibe.AttributeList, nodeID []int, depth int) (*privateKeyNode, error) {
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
		node.privateKey = wkdibe.KeyGen(params.params, master.masterKey, newAttrs)

		node.delegable = new(bool)
		node.left, node.right, *node.delegable = nil, nil, true
		return node, nil
	}

	// This private key should not be delegable
	newAttrs := newAttributeList(params, nodeID, attrs, depth, false)
	node.privateKey = wkdibe.KeyGen(params.params, master.masterKey, newAttrs)

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

func KeyGen(params *Params, master *MasterKey, attrs wkdibe.AttributeList, userNum int, newUser int) (*PrivateKey, error) {
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

func treeQualifyKey(params *Params, qNode *privateKeyNode, left int, right int, lEnd int, rEnd int, attrs wkdibe.AttributeList, nodeID []int, depth int) (*privateKeyNode, error) {
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
		node.privateKey = wkdibe.QualifyKey(params.params, qNode.privateKey, newAttrs)

		node.delegable = new(bool)
		node.left, node.right, *node.delegable = nil, nil, true
		return node, nil
	}

	newAttrs := newAttributeList(params, nodeID, attrs, depth, false)
	node.privateKey = wkdibe.QualifyKey(params.params, qNode.privateKey, newAttrs)

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
func QualifyKey(params *Params, qualify *PrivateKey, attrs wkdibe.AttributeList, lEnd int, rEnd int) (*PrivateKey, error) {
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

func min(x int, y int) int {
	if x < y {
		return x
	}
	return y
}

func max(x int, y int) int {
	if x > y {
		return x
	}
	return y
}

func treeEncrypt(params *Params, left int, right int, attrs wkdibe.AttributeList, lastAttrs wkdibe.AttributeList, preparedAttrs *wkdibe.PreparedAttributeList, revoc RevocationList, message *cryptutils.Encryptable, nodeID []int, depth int) (CiphertextList, error) {
	if left > right {
		return nil, nil
	}

	flag := false
	// This check can be reduced to O(log r), if we build segment tree on top of RevocationList
	// There are supposed to be no overlap entry in RevocationList
	cnt := 0
	l := right - left + 1
	for i := range revoc {
		if left <= revoc[i] && revoc[i] <= right {
			flag = true
			cnt = cnt + 1
			if cnt == l {
				return nil, nil
			}
		}
	}

	var newPreparedAttrs = new(wkdibe.PreparedAttributeList)
	*newPreparedAttrs = *preparedAttrs

	var newAttrs wkdibe.AttributeList
	newAttrs = newAttributeList(params, nodeID, attrs, depth, true)
	wkdibe.AdjustPreparedAttributeList(newPreparedAttrs, params.params, lastAttrs, newAttrs)

	if !flag {
		var cipher CiphertextList
		cipher = make(CiphertextList, 1, 1)
		cipher[0] = new(Ciphertext)

		cipher[0].ciphertext = wkdibe.EncryptPrepared(message, params.params, newPreparedAttrs)
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
	cipherLeft, err = treeEncrypt(params, left, mid, attrs, newAttrs, newPreparedAttrs, revoc, message, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	cipherRight, err = treeEncrypt(params, mid+1, right, attrs, newAttrs, newPreparedAttrs, revoc, message, nodeID, depth+1)
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
func Encrypt(params *Params, attrs wkdibe.AttributeList, revoc RevocationList, message *cryptutils.Encryptable) (*Cipher, error) {
	cipher := &Cipher{}
	var err error
	nodeID := make([]int, *params.userHeight, *params.userHeight)

	preparedAttrs := wkdibe.PrepareAttributeList(params.params, attrs)
	cipher.cipherlist, err = treeEncrypt(params, 1, *params.userSize, attrs, attrs, preparedAttrs, revoc, message, nodeID, 0)
	if err != nil {
		return nil, err
	}

	cipher.attrs = make(wkdibe.AttributeList)
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

func treeDecrypt(params *Params, pNode *privateKeyNode, left int, right int, cipher *Cipher, nodeID []int, depth int) *cryptutils.Encryptable {
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

				tmpPrivateKey := wkdibe.NonDelegableQualifyKey(params.params, pNode.privateKey, newAttrs)

				plaintext := wkdibe.Decrypt(cipher.cipherlist[i].ciphertext, tmpPrivateKey)
				return plaintext
			}
		}
		return nil
	}

	for i := range cipher.cipherlist {
		if left == *cipher.cipherlist[i].lEnd && right == *cipher.cipherlist[i].rEnd {
			newAttrs := newAttributeList(params, nodeID, cipher.attrs, depth, true)

			tmpPrivateKey := wkdibe.NonDelegableQualifyKey(params.params, pNode.privateKey, newAttrs)

			plaintext := wkdibe.Decrypt(cipher.cipherlist[i].ciphertext, tmpPrivateKey)
			return plaintext
		}
	}

	var plaintext *cryptutils.Encryptable
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
func Decrypt(params *Params, key *PrivateKey, cipher *Cipher) *cryptutils.Encryptable {
	nodeID := make([]int, *params.userHeight, *params.userHeight)
	plaintext := treeDecrypt(params, key.root, 1, *params.userSize, cipher, nodeID, 0)
	return plaintext
}
