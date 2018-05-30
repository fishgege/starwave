package main

import (
	"bytes"
	"crypto/rand"
	"io"
	"io/ioutil"
	"math/big"
	"testing"

	"github.com/ucbrise/starwave/core"
	roaque "github.com/ucbrise/starwave/crypto/roaque/csroaque/optimized"

	ipfs "github.com/ipfs/go-ipfs-api"
)

func check(err error) {
	if err != nil {
		panic(err)
	}
}

const (
	// MaxURIDepth is the maximum depth of a URI in STARWAVE.
	MaxURIDepth = core.MaxURILength

	// TimeDepth is the number of OAQUE slots to represent a fully qualified
	// time.
	TimeDepth = core.MaxTimeLength

	maxLeaves int = 65536
)

type interval struct {
	lEnd int
	rEnd int
}

func HelperAddFile(b *testing.B, filesize int, encrypt bool, tofs bool, setnewroot bool, numRevocations int, totUsers int) {
	b.StopTimer()

	numSlots := MaxURIDepth + TimeDepth
	myparams, _, err := roaque.Setup(rand.Reader, numSlots, maxLeaves)

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
				b.Fatal(err)
			}
			perms[i], perms[j.Uint64()] = perms[j.Uint64()], perms[i]
		}

		for i := 0; i != numRevocations; i++ {
			for j := perms[i].lEnd; j <= perms[i].rEnd; j++ {
				revocs = append(revocs, j)
			}
		}
	}

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
			file = encryptfile(path, myparams, &revocs, file)
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

const numRevoc = 5
const numUser = 2048

func BenchmarkAddFileNoEncrypt1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, false, false, false, numRevoc, numUser)
}

func BenchmarkAddFileNoEncrypt32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, false, false, false, numRevoc, numUser)
}

func BenchmarkAddFileNoEncrypt1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, false, false, false, numRevoc, numUser)
}

func BenchmarkAddFileNoEncrypt32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, false, false, false, numRevoc, numUser)
}

func BenchmarkAddFile1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, true, false, false, numRevoc, numUser)
}

func BenchmarkAddFile32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, true, false, false, numRevoc, numUser)
}

func BenchmarkAddFile1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, true, false, false, numRevoc, numUser)
}

func BenchmarkAddFile32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, true, false, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdateNoEncrypt1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, false, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdateNoEncrypt32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, false, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdateNoEncrypt1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, false, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdateNoEncrypt32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, false, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdate1KiB(b *testing.B) {
	HelperAddFile(b, 1<<10, true, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdate32KiB(b *testing.B) {
	HelperAddFile(b, 1<<15, true, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdate1MiB(b *testing.B) {
	HelperAddFile(b, 1<<20, true, true, false, numRevoc, numUser)
}

func BenchmarkAddFileAndUpdate32MiB(b *testing.B) {
	HelperAddFile(b, 1<<25, true, true, false, numRevoc, numUser)
}

func HelperReadFile(b *testing.B, filesize int, encrypt bool, tofs bool, numRevocations int, totUsers int) {
	b.StopTimer()

	numSlots := MaxURIDepth + TimeDepth
	myparams, mymk, err := roaque.Setup(rand.Reader, numSlots, maxLeaves)
	var mydk *roaque.PrivateKey

	//NOTE: Why is it starwave-bak?
	URI, err := core.ParseURIFromPath([]string{"a", "b", "c", "*"})
	if err != nil {
		b.Fatal(err)
	}

	//NOTE: Be careful about time
	TIME, err := core.ParseTimeFromPath([]uint16{2018, 5})
	if err != nil {
		b.Fatal(err)
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
				b.Fatal(err)
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
			b.Fatal(err)
		}
	}

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
		file = encryptfile(path, myparams, &revocs, file)
	}
	hash, err := s.Add(file)
	check(err)
	if tofs {
		newroothash := addtofs(s, nodeid, path, hash, false)
		setnewroothash(s, newroothash, false)
	}

	for i := 0; i < b.N; i++ {
		b.StartTimer()
		var reader io.ReadCloser
		//var namespace string
		if tofs {
			reader, err = s.Cat("/ipns/" + nodeid + "/" + path)
			check(err)
		} else {
			reader, err = s.Cat("/ipfs/" + hash)
			check(err)
		}

		var toread io.Reader = reader
		if encrypt {
			toread = decryptfile(reader, myparams, mydk)
		}

		_, err = ioutil.ReadAll(toread)
		check(err)

		b.StopTimer()

		reader.Close()
	}
}

func BenchmarkReadFileNoEncrypt1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, false, false, numRevoc, numUser)
}

func BenchmarkReadFileNoEncrypt32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, false, false, numRevoc, numUser)
}

func BenchmarkReadFileNoEncrypt1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, false, false, numRevoc, numUser)
}

func BenchmarkReadFileNoEncrypt32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, false, false, numRevoc, numUser)
}

func BenchmarkReadFile1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, true, false, numRevoc, numUser)
}

func BenchmarkReadFile32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, true, false, numRevoc, numUser)
}

func BenchmarkReadFile1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, true, false, numRevoc, numUser)
}

func BenchmarkReadFile32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, true, false, numRevoc, numUser)
}

func BenchmarkReadFileInSystemNoEncrypt1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, false, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystemNoEncrypt32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, false, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystemNoEncrypt1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, false, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystemNoEncrypt32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, false, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystem1KiB(b *testing.B) {
	HelperReadFile(b, 1<<10, true, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystem32KiB(b *testing.B) {
	HelperReadFile(b, 1<<15, true, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystem1MiB(b *testing.B) {
	HelperReadFile(b, 1<<20, true, true, numRevoc, numUser)
}

func BenchmarkReadFileInSystem32MiB(b *testing.B) {
	HelperReadFile(b, 1<<25, true, true, numRevoc, numUser)
}
