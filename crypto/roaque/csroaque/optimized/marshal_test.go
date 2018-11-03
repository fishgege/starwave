package csroaque_opt

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/samkumar/embedded-pairing/lang/go/wkdibe"
)

func TestMarshalKey(t *testing.T) {
	params, masterkey, err := Setup(rand.Reader, attrMaxSize, userMaxSize)
	if err != nil {
		t.Fatal(err)
	}

	attrs1 := wkdibe.AttributeList{2: big.NewInt(4)}
	attrs2 := wkdibe.AttributeList{2: big.NewInt(4), attrMaxSize - 1 - 2: big.NewInt(123)}

	key1 := genFromMasterHelper(t, params, masterkey, attrs1, 0, 4)
	key2 := qualifyHelper(t, params, key1, attrs2, *key1.lEnd, *key1.lEnd+2)

	m1, err := key1.Marshal(params, &attrs1, testCompressed)
	if err != nil {
		t.Fatal(err)
	}
	m2, err := key2.Marshal(params, &attrs2, testCompressed)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = UnMarshalKey(m1, testCompressed, false)
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = UnMarshalKey(m2, testCompressed, false)
	if err != nil {
		t.Fatal(err)
	}

	//TODO: Check this
}
