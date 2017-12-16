package sdroaque_opt

import (
	"io"
	"math"
	"math/big"

	"github.com/ucbrise/starwave/crypto/oaque"
	"vuvuzela.io/crypto/bn256"
)

type Params struct {
	userSize *int
	attrSize *int
	height   *int
	params   *oaque.Params
}

//	This should be out of band, and managed by namespace
//	userNumber *int

type MasterKey struct {
	masterKey *oaque.MasterKey
}

// private key for set S_ij
type setKey struct {
	nodeID         []int
	indexI, indexJ *int
	key            *oaque.PrivateKey
}

// Key[i] for sets S_{left[i],right[i]}.
type privateKeyNode struct {
	left, right *privateKeyNode
	// Contains private keys for S_i*
	keyList []*setKey
	// Indicate whether i of S_ij is delegable
	delegable *bool
}

// Contains O(log(k)+log(n)) privete keys for S_ij where S_ij covers at least one decryption
// permission.
type PrivateKey struct {
	lEnd, rEnd *int
	// Index starts from 0
	// attrs oaque.AttributeList
	root *privateKeyNode
}

type RevocationList []int

type Ciphertext struct {
	ciphertext     *oaque.Ciphertext
	nodeID         []int
	indexI, indexJ *int
}

type CiphertextList []*Ciphertext

type Cipher struct {
	cipherlist CiphertextList
	// TODO: attrs in cipher or in private key
	attrs oaque.AttributeList
}

func printNodeID(nodeID []int) {
	for i := range nodeID {
		print(nodeID[i])
	}
	println()
}

// Setup generates the system parameters, which may be made visible to an
// adversary. The parameter "l" is the total number of attributes supported
// (indexed from 1 to l-1). The parameter	"n" is the total number of users
// supported(indexed from 1 to n).
func Setup(random io.Reader, l int, n int) (*Params, *MasterKey, error) {
	params := &Params{}
	masterKey := &MasterKey{}
	var err error

	params.userSize, params.attrSize, params.height = new(int), new(int), new(int)
	*params.height = int(math.Ceil(math.Log2(float64(n))))
	//	*params.userSize = int(math.Floor(math.Exp2(float64(*params.height))))
	*params.userSize = int(math.Floor(math.Exp2(float64(*params.height))))
	*params.attrSize = l

	// The first several ceil(log2(n)) slots represents i in S_{ij}. The latter ceil(log2(n) represents
	// j in S_{ij}.
	params.params, masterKey.masterKey, err = oaque.Setup(random, (*params.height+*params.height)+l)
	if err != nil {
		return nil, nil, err
	}

	return params, masterKey, nil
}

// Return a new AttributeList contains original attrs and position of node vi and vj of S_ij
func newAttributeList(params *Params, nodeID []int, depthI int, depthJ int, attrs oaque.AttributeList, delegable bool) oaque.AttributeList {

	// NOTE: Assume attributeIndex is int
	newAttr := make(oaque.AttributeList)
	for index := range attrs {
		newAttr[oaque.AttributeIndex(*params.height+*params.height+int(index))] = attrs[index]
	}

	//TODO: Add hash function here or inside oaque
	for i := 0; i < depthI; i++ {
		newAttr[oaque.AttributeIndex(i)] = big.NewInt(int64(nodeID[i]))
	}

	if !delegable {
		for i := depthI; i < *params.height; i++ {
			newAttr[oaque.AttributeIndex(i)] = nil
		}
	}

	for i := 0; i < depthJ; i++ {
		newAttr[oaque.AttributeIndex(*params.height+i)] = big.NewInt(int64(nodeID[i]))
	}

	return newAttr
}

/*func Copy(nodeA []int, nodeB []int) {
	println("begin Copy")
	println(len(nodeB))
	for i := range nodeB {
		nodeA = append(nodeA, nodeB[i])
	}
	println(len(nodeA))
	println(nodeA)
	println("end Copy")
}*/

func treeKeyGen2(params *Params, master *MasterKey, attrs oaque.AttributeList, left int, right int, lEnd int, rEnd int, nodeID []int, depthI int, depthJ int, keyList []*setKey) error {
	if left >= right {
		return nil
	}

	var err error
	mid := (left + right) / 2

	if rEnd < mid {
		nodeID[depthJ] = 1

		newAttrs := newAttributeList(params, nodeID, depthI, depthJ+1, attrs, true)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)
		if err != nil {
			return err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depthI
		*tmpKey.indexJ = depthJ + 1
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		keyList = append(keyList, tmpKey)

		nodeID[depthJ] = 0

		err = treeKeyGen2(params, master, attrs, left, mid, lEnd, rEnd, nodeID, depthI, depthJ+1, keyList)
		if err != nil {
			return err
		}

		return nil

	} else {
		nodeID[depthJ] = 0

		newAttrs := newAttributeList(params, nodeID, depthI, depthJ+1, attrs, true)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)
		if err != nil {
			return err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depthI
		*tmpKey.indexJ = depthJ + 1
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		keyList = append(keyList, tmpKey)

		nodeID[depthJ] = 1

		err = treeKeyGen2(params, master, attrs, mid+1, right, lEnd, rEnd, nodeID, depthI, depthJ+1, keyList)
		if err != nil {
			return err
		}

		return nil
	}
}

// Generate keys for a single leaf index.
func treeKeyGen(params *Params, master *MasterKey, attrs oaque.AttributeList, left int, right int, lEnd int, rEnd int, nodeID []int, depth int) (*privateKeyNode, error) {
	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	var err error
	node := &privateKeyNode{}

	node.keyList = make([]*setKey, 0, *params.height)

	//	println(left, right, lEnd, rEnd)

	//	This private key should be delegable
	if lEnd <= left && right <= rEnd {
		newAttrs := newAttributeList(params, nodeID, depth, depth, attrs, true)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)
		if err != nil {
			return nil, err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depth
		*tmpKey.indexJ = *tmpKey.indexI
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		node.keyList = append(node.keyList, tmpKey)

		node.delegable = new(bool)
		node.left, node.right, *node.delegable = nil, nil, true
		return node, nil
	}

	// This private key should not be delegable

	mid := (left + right) / 2 // Note: it should be div

	if lEnd <= mid && mid+1 <= rEnd {
		newAttrs := newAttributeList(params, nodeID, depth, depth, attrs, false)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)
		if err != nil {
			return nil, err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depth
		*tmpKey.indexJ = *tmpKey.indexI
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)
		//		println(left, right, lEnd, rEnd)

		node.keyList = append(node.keyList, tmpKey)

		//node.delegable = new(bool)
		//node.left, node.right, *node.delegable = nil, nil, false
		//return node, nil
	} else {
		err = treeKeyGen2(params, master, attrs, left, right, lEnd, rEnd, nodeID, depth, depth, node.keyList)
		//	node., err = oaque.KeyGen(nil, params.params, master.masterKey, newAttrs)
		if err != nil {
			return nil, err
		}
	}

	nodeID[depth] = 0
	node.left, err = treeKeyGen(params, master, attrs, left, mid, lEnd, rEnd, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	node.right, err = treeKeyGen(params, master, attrs, mid+1, right, lEnd, rEnd, nodeID, depth+1)
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
	nodeID := make([]int, *params.height, *params.height)

	key.root, err = treeKeyGen(params, master, attrs, 1, *params.userSize, lEnd, rEnd, nodeID, 0)
	if err != nil {
		return nil, err
	}

	/*	key.setKey = make([]*privateKeyNode, newUser, newUser)
		for i := lEnd; i <= rEnd; i++ {
			id := i - lEnd
			key.setKey[id], err = treeKeyGen(params, master, attrs, leafIndex(*params.userSize, i))
			if err != nil {
				return nil, err
			}
		}*/

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd, *key.rEnd = lEnd, rEnd
	//	key.attrs = make(oaque.AttributeList)
	//	for index := range attrs {
	//		key.attrs[index] = attrs[index]
	//	}
	return key, nil
}

func treeQualifyKey3(params *Params, qKey *oaque.PrivateKey, attrs oaque.AttributeList, left int, right int, lEnd int, rEnd int, nodeID []int, depthI int, depthJ int, keyList []*setKey) error {
	if left >= right {
		return nil
	}

	var err error
	mid := (left + right) / 2

	//	println(left, right, lEnd, rEnd)
	if rEnd < mid {
		nodeID[depthJ] = 1

		newAttrs := newAttributeList(params, nodeID, depthI, depthJ+1, attrs, true)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.QualifyKey(nil, params.params, qKey, newAttrs)
		if err != nil {
			return err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depthI
		*tmpKey.indexJ = depthJ + 1
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		keyList = append(keyList, tmpKey)

		nodeID[depthJ] = 0

		err = treeQualifyKey3(params, qKey, attrs, left, mid, lEnd, rEnd, nodeID, depthI, depthJ+1, keyList)
		if err != nil {
			return err
		}

		return nil

	} else {
		nodeID[depthJ] = 0

		newAttrs := newAttributeList(params, nodeID, depthI, depthJ+1, attrs, true)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.QualifyKey(nil, params.params, qKey, newAttrs)
		if err != nil {
			return err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depthI
		*tmpKey.indexJ = depthJ + 1
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		keyList = append(keyList, tmpKey)

		nodeID[depthJ] = 1

		err = treeQualifyKey3(params, qKey, attrs, mid+1, right, lEnd, rEnd, nodeID, depthI, depthJ+1, keyList)
		if err != nil {
			return err
		}

		return nil
	}
}

func treeQualifyKey2(params *Params, qKey *oaque.PrivateKey, attrs oaque.AttributeList, left int, right int, lEnd int, rEnd int, nodeID []int, depth int) (*privateKeyNode, error) {
	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	//	println(left, right, lEnd, rEnd)

	var err error
	node := &privateKeyNode{}

	node.keyList = make([]*setKey, 0, *params.height)

	//	This private key should be delegable
	if lEnd <= left && right <= rEnd {
		newAttrs := newAttributeList(params, nodeID, depth, depth, attrs, true)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.QualifyKey(nil, params.params, qKey, newAttrs)
		if err != nil {
			return nil, err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depth
		*tmpKey.indexJ = *tmpKey.indexI
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		node.keyList = append(node.keyList, tmpKey)

		node.delegable = new(bool)
		node.left, node.right, *node.delegable = nil, nil, true
		return node, nil
	}

	// This private key should not be delegable

	mid := (left + right) / 2 // Note: it should be div

	if lEnd <= mid && mid+1 <= rEnd {
		newAttrs := newAttributeList(params, nodeID, depth, depth, attrs, false)

		tmpKey := &setKey{}
		tmpKey.key, err = oaque.QualifyKey(nil, params.params, qKey, newAttrs)
		if err != nil {
			return nil, err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI = depth
		*tmpKey.indexJ = *tmpKey.indexI
		tmpKey.nodeID = make([]int, len(nodeID), len(nodeID))
		copy(tmpKey.nodeID, nodeID)

		node.keyList = append(node.keyList, tmpKey)

		//		node.delegable = new(bool)
		//		node.left, node.right, *node.delegable = nil, nil, false
		//		return node, nil
	} else {
		err = treeQualifyKey3(params, qKey, attrs, left, right, lEnd, rEnd, nodeID, depth, depth, node.keyList)
		if err != nil {
			return nil, err
		}
	}

	nodeID[depth] = 0
	node.left, err = treeQualifyKey2(params, qKey, attrs, left, mid, lEnd, rEnd, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	node.right, err = treeQualifyKey2(params, qKey, attrs, mid+1, right, lEnd, rEnd, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	node.delegable = new(bool)
	*node.delegable = false
	//nodeID[depth] = nil
	return node, err
}

func treeQualifyKey(params *Params, qNode *privateKeyNode, attrs oaque.AttributeList, left int, right int, lEnd int, rEnd int, nodeID []int, depth int) (*privateKeyNode, error) {
	if qNode == nil {
		return nil, nil
	}

	if left > right {
		return nil, nil
	}

	if right < lEnd || rEnd < left {
		return nil, nil
	}

	if *qNode.delegable {
		node, err := treeQualifyKey2(params, qNode.keyList[0].key, attrs, left, right, lEnd, rEnd, nodeID, depth)
		if err != nil {
			return nil, err
		}

		return node, nil
	}

	var err error
	node := &privateKeyNode{}

	node.keyList = make([]*setKey, 0, len(qNode.keyList))

	//TODO: need reconstruction

	for i := range qNode.keyList {
		newAttrs := newAttributeList(params, qNode.keyList[i].nodeID, *qNode.keyList[i].indexI, *qNode.keyList[i].indexJ, attrs, false)
		tmpKey := &setKey{}
		tmpKey.key, err = oaque.QualifyKey(nil, params.params, qNode.keyList[i].key, newAttrs)
		if err != nil {
			return nil, err
		}

		tmpKey.indexI, tmpKey.indexJ = new(int), new(int)
		*tmpKey.indexI, *tmpKey.indexJ = *qNode.keyList[i].indexI, *qNode.keyList[i].indexJ
		tmpKey.nodeID = make([]int, len(qNode.keyList[i].nodeID), len(qNode.keyList[i].nodeID))
		copy(tmpKey.nodeID, qNode.keyList[i].nodeID)

		node.keyList = append(node.keyList, tmpKey)
	}

	mid := (left + right) / 2 // Note: it should be div

	nodeID[depth] = 0
	node.left, err = treeQualifyKey(params, qNode.left, attrs, left, mid, lEnd, rEnd, nodeID, depth+1)
	if err != nil {
		return nil, err
	}

	nodeID[depth] = 1
	node.right, err = treeQualifyKey(params, qNode.right, attrs, mid+1, right, lEnd, rEnd, nodeID, depth+1)
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
		panic("Cannot generate key which is out bound of given key")
	}

	key := &PrivateKey{}

	key.lEnd, key.rEnd = new(int), new(int)
	*key.lEnd = lEnd
	*key.rEnd = rEnd

	var err error
	nodeID := make([]int, *params.height, *params.height)

	key.root, err = treeQualifyKey(params, qualify.root, attrs, 1, *params.userSize, lEnd, rEnd, nodeID, 0)
	if err != nil {
		return nil, err
	}

	/*	key.setKey = make([]*privateKeyNode, rEnd-lEnd+1, rEnd-lEnd+1)

		// qualify.lEnd <= lEnd <= rEnd <= qualify.rEnd
		for i := lEnd; i <= rEnd; i++ {
			qualifyIndex := i - *qualify.lEnd
			keyIndex := i - lEnd
			for j := 0; j < len(qualify.setKey[qualifyIndex].privateKey); j++ {
				var err error
				key.setKey[keyIndex], err = qualifyKeyNode(params, qualify.setKey[qualifyIndex], attrs)
				if err != nil {
					return nil, err
				}
			}
		}

		key.attrs = make(oaque.AttributeList)
		for index := range attrs {
			key.attrs[index] = attrs[index]
		}*/

	return key, nil
}

/*func checkOutTwo(revocNode []bool, index int) bool {
	return (index == 1) || (revocNode[index<<1] && revocNode[(index<<1)+1])
}

func checkOutOne(revocNode []bool, index int) bool {
	return (revocNode[index<<1] && !revocNode[(index<<1)+1]) ||
		(!revocNode[index<<1] && revocNode[(index<<1)+1])
}*/

func newCipher(params *Params, nodeID []int, indexI int, indexJ int, attrs oaque.AttributeList, message *bn256.GT) (*Ciphertext, error) {
	var err error
	tmpCipher := &Ciphertext{}
	newAttrs := newAttributeList(params, nodeID, indexI, indexJ, attrs, true)

	tmpCipher.indexI, tmpCipher.indexJ = new(int), new(int)
	*tmpCipher.indexI, *tmpCipher.indexJ = indexI, indexJ
	tmpCipher.nodeID = make([]int, len(nodeID), len(nodeID))
	copy(tmpCipher.nodeID, nodeID)

	tmpCipher.ciphertext, err = oaque.Encrypt(nil, params.params, newAttrs, message)
	if err != nil {
		return nil, err
	}
	return tmpCipher, nil
}

// Find all  [v_{i_1} ,v_{i_2} ,...v_{i_l}] where
// (i) all of v_{i_1} ,v_{i_2} ,...v_{i_{l−1}} have outdegree 1 in ST(R)
// (ii) v_{i_l} is either a leaf or a node with outdegree 2 and
// (iii) the parent of v_{i_1} is either a node of outdegree 2 or the root.

func treeEncrypt(params *Params, left int, right int, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT, nodeID []int, depth int, indexI int, lastState int) (CiphertextList, error) {
	if left > right {
		return nil, nil
	}

	state := 0
	mid := (left + right) / 2

	if left < right {
		for i := range revoc {
			if left <= revoc[i] && revoc[i] <= mid {
				state |= 1
			}
			if mid+1 <= revoc[i] && revoc[i] <= right {
				state |= 2
			}
			if state == 3 {
				break
			}
		}
	} else {
		for i := range revoc {
			if mid == revoc[i] {
				state = 3
				break
			}
		}
		if lastState == 3 {
			return nil, nil
		}
	}

	if state == 0 {
		return nil, nil
	}

	cipherMid := make(CiphertextList, 0, 1)

	if lastState != 3 && state == 3 {
		//		println("indexI: ", indexI)
		//		println("depth: ", depth)
		tmpCipher, err := newCipher(params, nodeID, indexI, depth, attrs, message)
		if err != nil {
			return nil, err
		}

		cipherMid = append(cipherMid, tmpCipher)

		if left == right {
			return cipherMid, nil
		}
	}

	if lastState == 3 && state != 3 {
		lastState = state
		indexI = depth
	} else if lastState != 3 && state == 3 {
		lastState = state
		indexI = depth
	}

	var err error
	var cipherLeft, cipherRight CiphertextList

	if (state & 1) == 1 {
		//		println("left: %d right: %d depth: %d height: %d\n", left, right, depth, *params.height)
		//		println(state)
		nodeID[depth] = 0
		cipherLeft, err = treeEncrypt(params, left, mid, attrs, revoc, message, nodeID, depth+1, indexI, lastState)
		if err != nil {
			return nil, err
		}
	}

	if ((state >> 1) & 1) == 1 {
		nodeID[depth] = 1
		cipherRight, err = treeEncrypt(params, mid+1, right, attrs, revoc, message, nodeID, depth+1, indexI, lastState)
		if err != nil {
			return nil, err
		}
	}

	cipherlist := make(CiphertextList, 0, len(cipherLeft)+len(cipherRight)+len(cipherMid))

	if len(cipherLeft) != 0 {
		cipherlist = append(cipherlist, cipherLeft...)
	}

	if len(cipherMid) != 0 {
		cipherlist = append(cipherlist, cipherMid...)
	}

	if len(cipherRight) != 0 {
		cipherlist = append(cipherlist, cipherRight...)
	}

	return cipherlist, nil
}

// No function for revocation, since this is a stateless revocation scheme. User
// only need to specify revocation list along with URI during encryption.

// Encrypt first find sets which cover all the unrevoked leaves, and then
// encrypts message under those nodes' keys. The set covering algorithm used here
// is Subset Difference(SD).
func Encrypt(params *Params, attrs oaque.AttributeList, revoc RevocationList, message *bn256.GT) (*Cipher, error) {
	cipher := &Cipher{}
	var err error

	cipher.attrs = make(oaque.AttributeList)
	for index := range attrs {
		cipher.attrs[index] = attrs[index]
	}

	if revoc == nil {
		cipher.cipherlist = make(CiphertextList, 0, 2)

		tmpCipher, err := newCipher(params, []int{0}, 0, 1, attrs, message)
		if err != nil {
			return nil, err
		}
		cipher.cipherlist = append(cipher.cipherlist, tmpCipher)

		tmpCipher, err = newCipher(params, []int{1}, 0, 1, attrs, message)
		if err != nil {
			return nil, err
		}
		cipher.cipherlist = append(cipher.cipherlist, tmpCipher)

		return cipher, nil
	}

	nodeID := make([]int, *params.height, *params.height)
	cipher.cipherlist, err = treeEncrypt(params, 1, *params.userSize, attrs, revoc, message, nodeID, 0, 0, 3)
	if err != nil {
		return nil, err
	}

	/*	println("cipher")
		for i, tmp := range cipher.cipherlist {
			println("go %d", i)
			for j := range tmp.nodeID {
				println(tmp.nodeID[j])
			}
			println("index")
			println(*tmp.indexI)
			println(*tmp.indexJ)
		}*/
	return cipher, nil
}

func checkSubset(nodeA []int, indexA int, nodeB []int, indexB int) bool {
	if indexA > indexB {
		return false
	}

	for i := 0; i < indexA; i++ {
		if nodeA[i] != nodeB[i] {
			return false
		}
	}

	return true
}

func checkEqual(nodeA []int, indexA int, nodeB []int, indexB int) bool {
	if indexA != indexB {
		return false
	}

	for i := 0; i < indexA; i++ {
		if nodeA[i] != nodeB[i] {
			return false
		}
	}

	return true
}

func treeDecrypt(params *Params, qNode *privateKeyNode, cipher *Cipher) *bn256.GT {
	if qNode == nil {
		return nil
	}

	keyList := qNode.keyList
	cipherlist := cipher.cipherlist

	if *qNode.delegable {
		for i := range cipherlist {
			//NOTE: might be optimized
			for j := range keyList {
				if checkSubset(keyList[j].nodeID, *keyList[j].indexI, cipherlist[i].nodeID, *cipherlist[i].indexI) && checkSubset(keyList[j].nodeID, *keyList[j].indexJ, cipherlist[i].nodeID, *cipherlist[i].indexJ) {
					newAttrs := newAttributeList(params, cipherlist[i].nodeID, *cipherlist[i].indexI, *cipherlist[i].indexJ, cipher.attrs, true)

					tmpPrivateKey := oaque.NonDelegableKey(params.params, keyList[j].key, newAttrs)

					plaintext := oaque.Decrypt(tmpPrivateKey, cipher.cipherlist[i].ciphertext)
					return plaintext
				}
			}
		}
	} else {
		for i := range cipherlist {
			//NOTE: might be optimized
			for j := range keyList {
				if checkEqual(keyList[j].nodeID, *keyList[j].indexI, cipherlist[i].nodeID, *cipherlist[i].indexI) && checkSubset(keyList[j].nodeID, *keyList[j].indexJ, cipherlist[i].nodeID, *cipherlist[i].indexJ) {
					newAttrs := newAttributeList(params, cipherlist[i].nodeID, *cipherlist[i].indexI, *cipherlist[i].indexJ, cipher.attrs, true)

					tmpPrivateKey := oaque.NonDelegableKey(params.params, keyList[j].key, newAttrs)

					plaintext := oaque.Decrypt(tmpPrivateKey, cipher.cipherlist[i].ciphertext)
					return plaintext
				}
			}
		}
	}

	var plaintext *bn256.GT

	plaintext = treeDecrypt(params, qNode.left, cipher)
	if plaintext != nil {
		return plaintext
	}

	plaintext = treeDecrypt(params, qNode.right, cipher)
	if plaintext != nil {
		return plaintext
	}

	return nil
}

// Decrypt recovers the original message from the provided ciphertext, using
// the provided private key.
func Decrypt(params *Params, key *PrivateKey, cipher *Cipher) *bn256.GT {

	//	nodeID := make([]int, *params.userHeight, *params.userHeight)
	plaintext := treeDecrypt(params, key.root, cipher) //, nodeID, 0)
	return plaintext
}
