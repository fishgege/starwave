package swbind

import (
	"crypto/rand"
	"io/ioutil"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/immesys/bw2bind"
	"github.com/ucbrise/starwave/starwave"
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
	cl := ConnectOrExit("")

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

func BenchmarkSubscribe(b *testing.B) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

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

	/* Encrypt the message */
	authority, _, err := cl.ResolveRegistry(nsvk)
	if err != nil {
		b.Fatal(err)
	}

	hd := new(starwave.HierarchyDescriptor)
	success := hd.Unmarshal(GetCommentInEntity(authority.GetContent()))
	if !success {
		b.Fatal("Invalid hierarchy descriptor in namespace authority")
	}

	perm, err := starwave.ParsePermission("a/b/c/d/e/f", time.Now())
	if err != nil {
		b.Fatal(err)
	}

	po, err = cl.encryptPO(rand.Reader, hd, perm, po)
	if po == nil {
		b.Fatal("Could not encrypt payload object")
	} else if err != nil {
		b.Fatal(err)
	}

	/* Now, spawn threads to actually send this as fast as possible */

	uri := nsvk + "/a/b/c/d/e/f"

	var finished uint32 = 0

	publishfunc := func() {
		for atomic.LoadUint32(&finished) == 0 {
			cl.BW2Client.Publish(&bw2bind.PublishParams{
				URI:            uri,
				AutoChain:      true,
				PayloadObjects: []bw2bind.PayloadObject{po},
			})
		}
	}

	ncpu := runtime.NumCPU()
	runtime.GOMAXPROCS(runtime.NumCPU())

	nthreads := ncpu - 3
	if nthreads < 1 {
		b.Fatal("Not enough CPUs for this benchmark")
	}
	for i := 0; i != nthreads; i++ {
		go publishfunc()
	}

	scl := ConnectOrExit("")
	_, err = scl.SetEntityFile("subscribe.ent")
	check(err)

	b.StartTimer()

	msgs, err := scl.Subscribe(&bw2bind.SubscribeParams{
		URI: uri,
	})
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		_ = <-msgs
	}

	atomic.StoreUint32(&finished, 1)
}

func BenchmarkQuery(b *testing.B) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

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

	cl.Publish(&bw2bind.PublishParams{
		URI:            uri,
		AutoChain:      true,
		PayloadObjects: []bw2bind.PayloadObject{po},
		Persist:        true,
	})

	_, err = cl.SetEntityFile("subscribe.ent")
	check(err)

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		_, err := cl.QueryOne(&bw2bind.QueryParams{
			URI: uri,
		})
		b.StopTimer()
		if err != nil {
			b.Fatal(err)
		}
		b.StartTimer()
	}
}

func BenchmarkCreateDOT(b *testing.B) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

	_, err := cl.SetEntityFile("ns.ent")
	check(err)

	dotentvkbytes, err := ioutil.ReadFile(".dotent.done")
	check(err)
	dotentvk := string(dotentvkbytes)

	nsvkbytes, err := ioutil.ReadFile(".ns.done")
	check(err)
	nsvk := string(nsvkbytes)

	uri := nsvk + "/a/b/c/d/e/g"

	b.StartTimer()

	for i := 0; i < b.N; i++ {
		cl.BW2Client.CreateDOT(&bw2bind.CreateDOTParams{
			To:                dotentvk,
			URI:               uri,
			AccessPermissions: "C",
		})
	}
}
