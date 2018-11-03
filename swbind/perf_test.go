package swbind

import (
	"crypto/rand"
	"io/ioutil"
	"runtime"
	"sync/atomic"
	"testing"
	"time"

	"github.com/samkumar/bw2bind"
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

func HelperPublish(b *testing.B, msgsize int, encrypt bool, disablecache bool) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

	if disablecache {
		cl.disablecache()
	}

	nsvkbytes, err := ioutil.ReadFile(".ns.done")
	check(err)
	nsvk := string(nsvkbytes)

	_, err = cl.SetEntityFile("publish.ent")
	check(err)

	// Construct message
	buf := make([]byte, msgsize)
	_, err = rand.Read(buf)
	check(err)

	po, err := bw2bind.LoadBasePayloadObjectPO(bw2bind.PONumBlob, buf)
	check(err)

	uri := nsvk + "/a/b/c/d/e/f"

	b.StartTimer()

	if encrypt {
		for i := 0; i < b.N; i++ {
			cl.Publish(&bw2bind.PublishParams{
				URI:            uri,
				AutoChain:      true,
				PayloadObjects: []bw2bind.PayloadObject{po},
			})
		}
	} else {
		for i := 0; i < b.N; i++ {
			cl.BW2Client.Publish(&bw2bind.PublishParams{
				URI:            uri,
				AutoChain:      true,
				PayloadObjects: []bw2bind.PayloadObject{po},
			})
		}
	}
}

func BenchmarkPublishEncrypt1KiB(b *testing.B) {
	HelperPublish(b, 1<<10, true, false)
}

func BenchmarkPublishEncrypt32KiB(b *testing.B) {
	HelperPublish(b, 1<<15, true, false)
}

func BenchmarkPublishEncrypt1MiB(b *testing.B) {
	HelperPublish(b, 1<<20, true, false)
}

func BenchmarkPublishEncrypt1KiBNoCache(b *testing.B) {
	HelperPublish(b, 1<<10, true, true)
}

func BenchmarkPublishEncrypt32KiBNoCache(b *testing.B) {
	HelperPublish(b, 1<<15, true, true)
}

func BenchmarkPublishEncrypt1MiBNoCache(b *testing.B) {
	HelperPublish(b, 1<<20, true, true)
}

func BenchmarkPublishNoEncrypt1KiB(b *testing.B) {
	HelperPublish(b, 1<<10, false, false)
}

func BenchmarkPublishNoEncrypt32KiB(b *testing.B) {
	HelperPublish(b, 1<<15, false, false)
}

func BenchmarkPublishNoEncrypt1MiB(b *testing.B) {
	HelperPublish(b, 1<<20, false, false)
}

func HelperSubscribe(b *testing.B, msgsize int, encrypt bool, disablecache bool) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

	nsvkbytes, err := ioutil.ReadFile(".ns.done")
	check(err)
	nsvk := string(nsvkbytes)

	_, err = cl.SetEntityFile("publish.ent")
	check(err)

	// Create message
	buf := make([]byte, msgsize)
	_, err = rand.Read(buf)
	check(err)

	po, err := bw2bind.LoadBasePayloadObjectPO(bw2bind.PONumBlob, buf)
	check(err)

	/* Encrypt the message */
	if encrypt {
		authority, _, err := cl.ResolveRegistry(nsvk)
		if err != nil {
			b.Fatal(err)
		}

		hd := new(starwave.HierarchyDescriptor)
		success := hd.Unmarshal(GetCommentInEntity(authority.GetContent()), MarshalCompressed, MarshalChecked)
		if !success {
			b.Fatal("Invalid hierarchy descriptor in namespace authority")
		}

		perm, err := starwave.ParsePermission("a/b/c/d/e/f", time.Now())
		if err != nil {
			b.Fatal(err)
		}

		po, err = cl.encryptPO(rand.Reader, nsvk, hd, perm, po)
		if po == nil {
			b.Fatal("Could not encrypt payload object")
		} else if err != nil {
			b.Fatal(err)
		}
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

	nthreads := ncpu - 2
	if nthreads < 1 {
		b.Fatal("Not enough CPUs for this benchmark")
	}
	for i := 0; i != nthreads; i++ {
		go publishfunc()
	}

	// Wait so the queues on the router fill up a bit
	time.Sleep(5 * time.Second)

	scl := ConnectOrExit("")
	_, err = scl.SetEntityFile("subscribe.ent")
	check(err)

	if disablecache {
		scl.disablecache()
	}

	var msgs chan *bw2bind.SimpleMessage
	var handle string
	params := &bw2bind.SubscribeParams{
		URI: uri,
	}

	b.StartTimer()

	if encrypt {
		msgs, handle, err = scl.SubscribeH(params)
	} else {
		msgs, handle, err = scl.BW2Client.SubscribeH(params)
	}
	if err != nil {
		b.Fatal(err)
	}

	for i := 0; i < b.N; i++ {
		a := <-msgs
		if a == nil {
			panic(a)
		}
	}

	b.StopTimer()

	atomic.StoreUint32(&finished, 1)

	go func() {
		// Drain the channel
		for _ = range msgs {
		}
	}()

	// This may block until the channel is drained. I suspect it's because of
	// the bindings' event loop blocking.
	err = scl.Unsubscribe(handle)
	check(err)
}

func BenchmarkSubscribeEncrypt1KiB(b *testing.B) {
	HelperSubscribe(b, 1<<10, true, false)
}

func BenchmarkSubscribeEncrypt32KiB(b *testing.B) {
	HelperSubscribe(b, 1<<15, true, false)
}

func BenchmarkSubscribeEncrypt1MiB(b *testing.B) {
	HelperSubscribe(b, 1<<20, true, false)
}

func BenchmarkSubscribeEncrypt1KiBNoCache(b *testing.B) {
	HelperSubscribe(b, 1<<10, true, true)
}

func BenchmarkSubscribeEncrypt32KiBNoCache(b *testing.B) {
	HelperSubscribe(b, 1<<15, true, true)
}

func BenchmarkSubscribeEncrypt1MiBNoCache(b *testing.B) {
	HelperSubscribe(b, 1<<20, true, true)
}

func BenchmarkSubscribeNoEncrypt1KiB(b *testing.B) {
	HelperSubscribe(b, 1<<10, false, false)
}

func BenchmarkSubscribeNoEncrypt32KiB(b *testing.B) {
	HelperSubscribe(b, 1<<15, false, false)
}

func BenchmarkSubscribeNoEncrypt1MiB(b *testing.B) {
	HelperSubscribe(b, 1<<20, false, false)
}

func HelperQuery(b *testing.B, msgsize int, encrypt bool) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

	nsvkbytes, err := ioutil.ReadFile(".ns.done")
	check(err)
	nsvk := string(nsvkbytes)

	_, err = cl.SetEntityFile("publish.ent")
	check(err)

	buf := make([]byte, msgsize)
	_, err = rand.Read(buf)
	check(err)

	po, err := bw2bind.LoadBasePayloadObjectPO(bw2bind.PONumBlob, buf)
	check(err)

	uri := nsvk + "/a/b/c/d/e/f"

	pparams := &bw2bind.PublishParams{
		URI:            uri,
		AutoChain:      true,
		PayloadObjects: []bw2bind.PayloadObject{po},
		Persist:        true,
	}

	if encrypt {
		cl.Publish(pparams)
	} else {
		cl.BW2Client.Publish(pparams)
	}

	scl := ConnectOrExit("")
	_, err = scl.SetEntityFile("subscribe.ent")
	check(err)

	// Make sure to do a decryption (and signature verification, if applicable)
	scl.disablecache()

	b.StartTimer()
	if encrypt {
		for i := 0; i < b.N; i++ {
			msg, err := scl.QueryOne(&bw2bind.QueryParams{
				URI: uri,
			})
			if err != nil {
				b.Fatal(err)
			} else if len(msg.POs[0].GetContents()) != msgsize {
				b.Fatal("Retrieved message has the wrong length")
			}
		}
	} else {
		for i := 0; i < b.N; i++ {
			_, err := scl.BW2Client.QueryOne(&bw2bind.QueryParams{
				URI: uri,
			})
			if err != nil {
				b.Fatal(err)
			}
		}
	}
}

func BenchmarkQueryEncrypt1KiB(b *testing.B) {
	HelperQuery(b, 1<<10, true)
}

func BenchmarkQueryEncrypt32KiB(b *testing.B) {
	HelperQuery(b, 1<<15, true)
}

func BenchmarkQueryEncrypt1MiB(b *testing.B) {
	HelperQuery(b, 1<<20, true)
}

func BenchmarkQueryNoEncrypt1KiB(b *testing.B) {
	HelperQuery(b, 1<<10, false)
}

func BenchmarkQueryNoEncrypt32KiB(b *testing.B) {
	HelperQuery(b, 1<<15, false)
}

func BenchmarkQueryNoEncrypt1MiB(b *testing.B) {
	HelperQuery(b, 1<<20, false)
}

func HelperCreateDOT(b *testing.B, crypto bool) {
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
	if crypto {
		for i := 0; i < b.N; i++ {
			cl.CreateDOT(&bw2bind.CreateDOTParams{
				To:                dotentvk,
				URI:               uri,
				AccessPermissions: "C",
			})
		}
	} else {
		for i := 0; i < b.N; i++ {
			cl.BW2Client.CreateDOT(&bw2bind.CreateDOTParams{
				To:                dotentvk,
				URI:               uri,
				AccessPermissions: "C",
			})
		}
	}
}

func BenchmarkCreateDOTCrypto(b *testing.B) {
	HelperCreateDOT(b, true)
}

func BenchmarkCreateDOTNoCrypto(b *testing.B) {
	HelperCreateDOT(b, false)
}

func HelperBuildDOTChain(b *testing.B, crypto bool) {
	b.StopTimer()

	bw2bind.SilenceLog()
	cl := ConnectOrExit("")

	_, err := cl.SetEntityFile("subscribe.ent")
	check(err)

	subscribevkbytes, err := ioutil.ReadFile(".subscribe.done")
	check(err)
	subscribevk := string(subscribevkbytes)

	nsvkbytes, err := ioutil.ReadFile(".ns.done")
	check(err)
	nsvk := string(nsvkbytes)

	uri := nsvk + "/a/b/c/d/e/f"

	perm, err := starwave.ParsePermission("a/b/c/d/e/f", time.Now())
	check(err)

	b.StartTimer()
	if crypto {
		for i := 0; i < b.N; i++ {
			key, err := cl.ObtainKey(nsvk, perm, starwave.KeyTypeDecryption)
			if key == nil {
				panic("ObtainKey failed")
			} else if err != nil {
				panic(err)
			}
		}
	} else {
		for i := 0; i < b.N; i++ {
			chain, err := cl.BW2Client.BuildAnyChain(uri, "C", subscribevk)
			if chain == nil {
				panic("BuildAnyChain failed")
			} else if err != nil {
				panic(err)
			}
		}
	}
}

func BenchmarkBuildDOTChainCrypto(b *testing.B) {
	HelperBuildDOTChain(b, true)
}

func BenchmarkBuildDOTChainNoCrypto(b *testing.B) {
	HelperBuildDOTChain(b, false)
}
