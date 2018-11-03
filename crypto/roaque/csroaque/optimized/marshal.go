package csroaque_opt

import (
	"encoding/hex"
	"errors"
	"math/big"
	"strconv"

	"github.com/samkumar/embedded-pairing/lang/go/wkdibe"
)

// 16^5
const LeaveRangeMarshalledSize = 5

// 16^5
const TotLenMarshalledSize = 5

// 16^2
const AttrIdxMarshalledSize = 2

func PadString(tmp string, max int) string {
	l := len(tmp)
	for i := l; i < max; i++ {
		tmp = "0" + tmp
	}
	return tmp
}

func (c *Cipher) Marshal(compressed bool) []byte {
	marshalled := make([]byte, 0)

	for i := 0; i < len(c.cipherlist); i++ {
		tmp := c.cipherlist[i].ciphertext.Marshal(compressed)
		//copy(marshalled[tot:tot+l], tmp)
		marshalled = append(marshalled, tmp...)

		{
			tmpL := *c.cipherlist[i].lEnd
			tmpString := strconv.FormatUint(uint64(tmpL), 16)
			tmpString = PadString(tmpString, LeaveRangeMarshalledSize)
			marshalled = append(marshalled, tmpString...)
		}

		{
			tmpR := *c.cipherlist[i].rEnd
			tmpString := strconv.FormatUint(uint64(tmpR), 16)
			tmpString = PadString(tmpString, LeaveRangeMarshalledSize)
			marshalled = append(marshalled, tmpString...)
		}
	}

	tmpString := strconv.FormatUint(uint64(len(c.cipherlist)), 16)
	tmpString = PadString(tmpString, TotLenMarshalledSize)
	marshalled = append([]byte(tmpString), marshalled...)
	return marshalled
}

func (c *Cipher) UnMarshal(marshalled []byte, compressed bool, checked bool) bool {
	idx := 0
	totlen, err := strconv.ParseUint(string(marshalled[0:TotLenMarshalledSize]), 16, 64)
	if err != nil {
		return false
	}
	idx = TotLenMarshalledSize

	c.cipherlist = make(CiphertextList, totlen)

	for i := 0; i < int(totlen); i++ {
		tmp := &Ciphertext{}
		tmp.ciphertext = &wkdibe.Ciphertext{}
		ciphertextMarshalledSize := wkdibe.CiphertextMarshalledLength(compressed)
		err := tmp.ciphertext.Unmarshal(marshalled[idx:idx+ciphertextMarshalledSize], compressed, checked)
		if !err {
			return false
		}
		idx = idx + ciphertextMarshalledSize

		{
			t, err := strconv.ParseUint(string(marshalled[idx:idx+LeaveRangeMarshalledSize]), 16, 64)
			if err != nil {
				return false
			}
			tmp.lEnd = new(int)
			*tmp.lEnd = int(t)
			idx = idx + LeaveRangeMarshalledSize
		}

		{
			t, err := strconv.ParseUint(string(marshalled[idx:idx+LeaveRangeMarshalledSize]), 16, 64)
			if err != nil {
				return false
			}
			tmp.rEnd = new(int)
			*tmp.rEnd = int(t)
			idx = idx + LeaveRangeMarshalledSize
		}

		c.cipherlist[i] = tmp
	}

	return true
}

func AppendWithIndex(a []byte, b []byte) []byte {
	tmp := len(b)
	tmpString := strconv.FormatUint(uint64(tmp), 16)
	tmpString = PadString(tmpString, TotLenMarshalledSize)
	a = append(a, tmpString...)
	return append(a, b...)
}

func treeMarshal(pNode *privateKeyNode, left int, right int, compressed bool) ([]byte, error) {
	if left > right {
		return nil, nil
	}

	if pNode == nil {
		return nil, nil
	}

	res := make([]byte, 0)
	if *pNode.delegable {
		tmp := make([]byte, 0)
		{
			tmpString := strconv.FormatUint(uint64(left), 16)
			tmpString = PadString(tmpString, LeaveRangeMarshalledSize)
			tmp = append(tmp, tmpString...)
		}
		{
			tmpString := strconv.FormatUint(uint64(right), 16)
			tmpString = PadString(tmpString, LeaveRangeMarshalledSize)
			tmp = append(tmp, tmpString...)
		}
		tmp = append(tmp, hex.EncodeToString(pNode.privateKey.Marshal(compressed))...)
		res = AppendWithIndex(res, tmp)
	}

	mid := (left + right) / 2
	tmp, err := treeMarshal(pNode.left, left, mid, compressed)
	if err != nil {
		return nil, err
	}
	res = append(res, tmp...)

	tmp, err = treeMarshal(pNode.right, mid+1, right, compressed)
	if err != nil {
		return nil, err
	}
	res = append(res, tmp...)

	return res, nil
}

func MarshalAttrs(attrs wkdibe.AttributeList) ([]byte, error) {
	mattrs := make([]byte, 0)
	midx := make([]byte, 0)
	for idx, _ := range attrs {
		tmpString := strconv.FormatUint(uint64(idx), 16)
		tmpString = PadString(tmpString, AttrIdxMarshalledSize)
		midx = append(midx, []byte(tmpString)...)
	}

	for _, att := range attrs {
		tmp, err := att.MarshalText()
		if err != nil {
			return nil, err
		}
		mattrs = AppendWithIndex(mattrs, []byte(hex.EncodeToString(tmp)))
	}
	res := make([]byte, 0)
	res = AppendWithIndex(res, midx)
	return append(res, mattrs...), nil
}

func (key *PrivateKey) Marshal(params *Params, attrs *wkdibe.AttributeList, compressed bool) ([]byte, error) {
	res, err := treeMarshal(key.root, 1, *params.userSize, compressed)
	if err != nil {
		return nil, err
	}

	mattrs, err := MarshalAttrs(*attrs)
	if err != nil {
		return nil, err
	}

	tmp := make([]byte, 0)
	tmp = AppendWithIndex(tmp, mattrs)
	tmp = AppendWithIndex(tmp, res)
	return tmp, nil
}

type UnMarshalledKey struct {
	Key         *wkdibe.SecretKey
	Left, Right int
}

func UnMarshalIndex(marshalled []byte) (int, error) {
	totlen, err := strconv.ParseUint(string(marshalled), 16, 64)
	if err != nil {
		return 0, err
	}

	return int(totlen), nil
}

func UnMarshalIndexList(marshalled []byte) ([]int, error) {
	idx := 0
	res := make([]int, 0)
	for idx < len(marshalled) {
		t, err := strconv.ParseUint(string(marshalled[idx:idx+AttrIdxMarshalledSize]), 16, 64)
		if err != nil {
			return nil, err
		}
		res = append(res, int(t))
		idx = idx + AttrIdxMarshalledSize
	}
	return res, nil
}

func UnMarshalAttrsList(marshalled []byte, index []int) (*wkdibe.AttributeList, error) {
	idx := 0
	res := make(wkdibe.AttributeList)
	for i := 0; i < len(index); i++ {
		attrlen, err := UnMarshalIndex(marshalled[idx : idx+TotLenMarshalledSize])
		if err != nil {
			return nil, err
		}
		idx = idx + TotLenMarshalledSize

		tmpString, err := hex.DecodeString(string(marshalled[idx : idx+attrlen]))
		if err != nil {
			return nil, err
		}
		tmp := big.NewInt(0)
		tmp.UnmarshalText([]byte(tmpString))
		res[wkdibe.AttributeIndex(index[i])] = tmp
		idx = idx + attrlen
	}
	return &res, nil
}

func UnMarshalAttrs(marshalled []byte) (*wkdibe.AttributeList, error) {
	idxLen, err := UnMarshalIndex(marshalled[0:TotLenMarshalledSize])
	if err != nil {
		return nil, err
	}
	idxList, err := UnMarshalIndexList(marshalled[TotLenMarshalledSize : TotLenMarshalledSize+idxLen])
	if err != nil {
		return nil, err
	}
	attrsList, err := UnMarshalAttrsList(marshalled[TotLenMarshalledSize+idxLen:], idxList)
	if err != nil {
		return nil, err
	}

	return attrsList, nil
}

func UnMarshalInt(marshalled []byte) (int, error) {
	t, err := strconv.ParseUint(string(marshalled), 16, 64)
	if err != nil {
		return 0, err
	}

	return int(t), nil
}

func UnMarshalSingleKey(marshalled []byte, compressed bool, checked bool) (*UnMarshalledKey, error) {
	tmp := &UnMarshalledKey{}
	var err error
	tmp.Left, err = UnMarshalInt(marshalled[0:LeaveRangeMarshalledSize])
	if err != nil {
		return nil, err
	}

	tmp.Right, err = UnMarshalInt(marshalled[LeaveRangeMarshalledSize : 2*LeaveRangeMarshalledSize])
	if err != nil {
		return nil, err
	}

	tmpString, err := hex.DecodeString(string(marshalled[2*LeaveRangeMarshalledSize:]))
	if err != nil {
		return nil, err
	}
	tmp.Key = new(wkdibe.SecretKey)
	ok := tmp.Key.Unmarshal(tmpString, compressed, checked)
	if !ok {
		return nil, errors.New("UnMarshalSingleKey Error")
	}

	return tmp, nil
}

func UnMarshalKeySeq(marshalled []byte, compressed bool, checked bool) ([]*UnMarshalledKey, error) {
	idx := 0
	res := make([]*UnMarshalledKey, 0)
	for idx < len(marshalled) {
		keylen, err := UnMarshalIndex(marshalled[idx : idx+TotLenMarshalledSize])
		if err != nil {
			return nil, err
		}
		idx = idx + TotLenMarshalledSize

		tmp, err := UnMarshalSingleKey(marshalled[idx:idx+keylen], compressed, checked)
		if err != nil {
			return nil, err
		}
		idx = idx + keylen

		res = append(res, tmp)
	}
	return res, nil
}

func UnMarshalKey(marshalled []byte, compressed bool, checked bool) ([]*UnMarshalledKey, *wkdibe.AttributeList, error) {
	attrsLen, err := UnMarshalIndex(marshalled[0:TotLenMarshalledSize])
	if err != nil {
		return nil, nil, err
	}

	attrs, err := UnMarshalAttrs(marshalled[TotLenMarshalledSize : TotLenMarshalledSize+attrsLen])
	if err != nil {
		return nil, nil, err
	}

	keyLen, err := UnMarshalIndex(marshalled[TotLenMarshalledSize+attrsLen : TotLenMarshalledSize*2+attrsLen])
	if err != nil {
		return nil, nil, err
	}

	key, err := UnMarshalKeySeq(marshalled[TotLenMarshalledSize*2+attrsLen:TotLenMarshalledSize*2+attrsLen+keyLen], compressed, checked)
	if err != nil {
		return nil, nil, err
	}
	return key, attrs, nil
}
