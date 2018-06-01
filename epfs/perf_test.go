package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"io"
	"io/ioutil"
	"testing"
	"time"

	"github.com/immesys/bw2bind"
	"github.com/ucbrise/starwave/starwave"
	"github.com/ucbrise/starwave/swbind"

	ipfs "github.com/ipfs/go-ipfs-api"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

func HelperAddFile(b *testing.B, filesize int, encrypt bool, tofs bool, setnewroot bool) {
	b.StopTimer()

	bw2bind.SilenceLog()
	swc := swbind.ConnectOrExit("")
	//myvk := swc.SetEntityFromEnvironOrExit()
	swc.SetEntityFile("../swbind/ns.ent")
	myhd := swbind.HierarchyDescriptorFromEntity(swc.GetEntity())
	myparams := myhd.Params

	s := ipfs.NewLocalShell()

	idout, err := s.ID()
	handle(err)

	myself := idout.ID
	path := "a/b/c/d/e/f"

	for i := 0; i < b.N; i++ {
		buf := make([]byte, filesize)
		_, err := rand.Read(buf)
		check(err)

		bufreader := bytes.NewReader(buf)

		var file io.Reader = bufreader
		b.StartTimer()
		if encrypt {
			file = encryptfile(path, myparams, file)
		}
		hash, err := s.Add(file)
		if tofs {
			newroothash := addtofs(s, myself, path, hash, false)
			if setnewroot {
				setnewroothash(s, newroothash, false)
			}
		}
		b.StopTimer()

		if err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAddFileNoEncrypt1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, false, false, false)
}

func BenchmarkAddFileNoEncrypt32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, false, false, false)
}

func BenchmarkAddFileNoEncrypt1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, false, false, false)
}

func BenchmarkAddFileNoEncrypt32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, false, false, false)
}

func BenchmarkAddFile1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, true, false, false)
}

func BenchmarkAddFile32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, true, false, false)
}

func BenchmarkAddFile1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, true, false, false)
}

func BenchmarkAddFile32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, true, false, false)
}

func BenchmarkAddFileAndUpdateNoEncrypt1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, false, true, false)
}

func BenchmarkAddFileAndUpdateNoEncrypt32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, false, true, false)
}

func BenchmarkAddFileAndUpdateNoEncrypt1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, false, true, false)
}

func BenchmarkAddFileAndUpdateNoEncrypt32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, false, true, false)
}

func BenchmarkAddFileAndUpdate1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, true, true, false)
}

func BenchmarkAddFileAndUpdate32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, true, true, false)
}

func BenchmarkAddFileAndUpdate1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, true, true, false)
}

func BenchmarkAddFileAndUpdate32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, true, true, false)
}

func HelperReadFile(b *testing.B, filesize int, encrypt bool, tofs bool) {
	b.StopTimer()

	bw2bind.SilenceLog()
	swc := swbind.ConnectOrExit("")
	nsvk, err := swc.SetEntityFile("../swbind/ns.ent")
	check(err)
	myhd := swbind.HierarchyDescriptorFromEntity(swc.GetEntity())
	myparams := myhd.Params

	s := ipfs.NewLocalShell()

	idout, err := s.ID()
	handle(err)

	nodeid := idout.ID
	path := "a/b/c/d/e/f"

	buf := make([]byte, filesize)
	_, err = rand.Read(buf)
	check(err)

	bufreader := bytes.NewReader(buf)

	var file io.Reader = bufreader
	if encrypt {
		file = encryptfile(path, myparams, file)
	}
	hash, err := s.Add(file)
	check(err)
	if tofs {
		newroothash := addtofs(s, nodeid, path, hash, false)
		setnewroothash(s, newroothash, false)
	}

	swc = swbind.ConnectOrExit("")
	myvk, err := swc.SetEntityFile("../swbind/subscribe.ent")
	check(err)
	myhd = swbind.HierarchyDescriptorFromEntity(swc.GetEntity())

	perm, err := starwave.ParsePermission(path, time.Now())
	check(err)
	dparams, dkey := obtainkey(perm, swc, nsvk, myvk, myhd, false)

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		var reader io.ReadCloser
		var namespace string
		if tofs {
			enthash, zero, err := swc.ResolveLongAlias(nodeid[:32])
			handle(err)
			if zero {
				b.Fatalf("Could not resolve alias %s in BW2\n", nodeid[:32])
			}
			namespace = base64.URLEncoding.EncodeToString(enthash)

			reader, err = s.Cat("/ipns/" + nodeid + "/" + path)
			check(err)
		} else {
			reader, err = s.Cat("/ipfs/" + hash)
			check(err)

			namespace = nsvk
		}

		var toread io.Reader = reader
		if encrypt {
			if tofs {
				toread = decryptfile(reader, swc, namespace, myvk, myhd, false)
			} else {
				toread = decryptfilewithkey(reader, dparams, dkey)
			}
		}

		_, err = ioutil.ReadAll(toread)
		check(err)

		b.StopTimer()

		reader.Close()
	}
}

func BenchmarkReadFileNoEncrypt1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, false, false)
}

func BenchmarkReadFileNoEncrypt32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, false, false)
}

func BenchmarkReadFileNoEncrypt1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, false, false)
}

func BenchmarkReadFileNoEncrypt32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, false, false)
}

func BenchmarkReadFile1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, true, false)
}

func BenchmarkReadFile32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, true, false)
}

func BenchmarkReadFile1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, true, false)
}

func BenchmarkReadFile32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, true, false)
}

func BenchmarkReadFileInSystemNoEncrypt1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, false, true)
}

func BenchmarkReadFileInSystemNoEncrypt32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, false, true)
}

func BenchmarkReadFileInSystemNoEncrypt1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, false, true)
}

func BenchmarkReadFileInSystemNoEncrypt32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, false, true)
}

func BenchmarkReadFileInSystem1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, true, true)
}

func BenchmarkReadFileInSystem32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, true, true)
}

func BenchmarkReadFileInSystem1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, true, true)
}

func BenchmarkReadFileInSystem32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, true, true)
}
