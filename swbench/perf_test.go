package swbench

import (
	"crypto/rand"
	"io/ioutil"
	"testing"

	"github.com/immesys/bw2bind"
	"github.com/ucbrise/starwave/swbind"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func assert(cond bool) {
	if !cond {
		panic("Assertion failed")
	}
}

func BenchmarkPublish(b *testing.B) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := swbind.ConnectOrExit("")

	nsvkbytes, err := ioutil.ReadFile(".ns.done")
	check(err)
	nsvk := string(nsvkbytes)

	_, err = cl.SetEntityFile("publish.ent")
	check(err)

	// 1 MiB
	buf := make([]byte, 1024*1024)
	_, err = rand.Read(buf)
	check(err)

	po, err := bw2bind.LoadBasePayloadObjectPO(bw2bind.PONumBlob, buf)
	check(err)

	uri := nsvk + "/a/b/c/d/e/f"

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cl.Publish(&bw2bind.PublishParams{
			URI:            uri,
			AutoChain:      true,
			PayloadObjects: []bw2bind.PayloadObject{po},
		})
	}
}
