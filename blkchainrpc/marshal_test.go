package blkchainrpc

import (
	"crypto/rand"
	"math/big"
	"testing"

	"github.com/ucbrise/starwave/core"
	"github.com/ucbrise/starwave/crypto/oaque"
	roaque "github.com/ucbrise/starwave/crypto/roaque/csroaque/optimized"
)

const (
	// MaxURIDepth is the maximum depth of a URI in STARWAVE.
	MaxURIDepth = core.MaxURILength

	// TimeDepth is the number of OAQUE slots to represent a fully qualified
	// time.
	TimeDepth = core.MaxTimeLength

	maxLeaves int = 65536
)

const numRevocations = 5
const totUsers = 2048

type interval struct {
	lEnd int
	rEnd int
}

func TestRevocationList(t *testing.T) {
	var err error
	//miner := Setup("./miner")
	//Step1: Setup ZCash
	server := Setup("./server")
	client := Setup("./client")

	server.TxConfirmTime = "150"
	client.TxConfirmTime = "150"
	err = GetTAddr(server)
	if err != nil {
		t.Fatal("GetTaddr error")
	}
	err = GetZAddr(server)
	if err != nil {
		t.Fatal("GetZaddr error")
	}

	vkey, err := ExportViewingKey(server)
	if err != nil {
		t.Fatal("ExportViewingKey error")
	}

	err = ImportViewingKey(client, server.Zaddr, vkey)
	if err != nil {
		t.Fatal(err)
	}

	//Step2: Setup roaque
	numSlots := MaxURIDepth + TimeDepth
	myparams, mymk, err := roaque.Setup(rand.Reader, numSlots, maxLeaves)
	var mydk *roaque.PrivateKey

	//NOTE: Why is it starwave-bak?
	URI, err := core.ParseURIFromPath([]string{"a", "b", "c", "*"})
	if err != nil {
		t.Fatal(err)
	}

	//NOTE: Be careful about time
	TIME, err := core.ParseTimeFromPath([]uint16{2018, 5})
	if err != nil {
		t.Fatal(err)
	}
	attrs := core.AttributeSetFromPaths(URI, TIME, []byte{0x0})

	keyLen := maxLeaves / totUsers

	revocs := make(roaque.RevocationList, 0, numRevocations)
	{
		perms := make([]*interval, totUsers)
		for i, j := 0, 0; i != totUsers; i++ {
			tmp := &interval{lEnd: j + 1, rEnd: j + keyLen}
			perms[i] = tmp
			j = j + keyLen
		}

		for i := range perms {
			j, err := rand.Int(rand.Reader, new(big.Int).SetUint64((uint64)(i+1)))
			if err != nil {
				t.Fatal(err)
			}
			perms[i], perms[j.Uint64()] = perms[j.Uint64()], perms[i]
		}

		for i := 0; i != numRevocations; i++ {
			for j := perms[i].lEnd; j <= perms[i].rEnd; j++ {
				revocs = append(revocs, j)
			}
		}

		mydk, err = roaque.KeyGen(myparams, mymk, attrs, perms[numRevocations].lEnd, keyLen)
		if err != nil {
			t.Fatal(err)
		}
	}

	//Step3: Start testing
	tmpAttr := oaque.AttributeList(attrs)
	marshalled, err := mydk.Marshal(myparams, &tmpAttr)
	if err != nil {
		t.Fatal(err)
	}

	err = server.SendMarshalledData(marshalled)
	if err != nil {
		t.Fatal(err)
	}

	_, err = client.GenerateRevocList()
	if err != nil {
		t.Fatal(err)
	}
}
