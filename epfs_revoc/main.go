package main

import (
	"bytes"
	"crypto/rand"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	ipfs "github.com/ipfs/go-ipfs-api"
	"github.com/ucbrise/starwave/core"
	roaque "github.com/ucbrise/starwave/crypto/roaque/csroaque/optimized"
	"github.com/ucbrise/starwave/starwave"
)

const (
	MarshalCompressed = true
	MarshalChecked    = true
)

func handle(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(100)
	}
}

func addtofs(s *ipfs.Shell, nodeid string, path string, filehash string, verbose bool) string {
	newroothash, err := s.Patch("/ipns/"+nodeid, "add-link", path, "/ipfs/"+filehash)
	handle(err)

	if verbose {
		fmt.Printf("Updated directory tree: %s\n", newroothash)
	}
	return newroothash
}

func setnewroothash(s *ipfs.Shell, newroothash string, verbose bool) {
	err := s.Publish("", newroothash)
	handle(err)

	if verbose {
		fmt.Println("Published new root")
	}
}

func validatewrite(s *ipfs.Shell, fullpath string) (string, string) {
	idout, err := s.ID()
	handle(err)

	myself := idout.ID

	if !strings.HasPrefix(fullpath, "/ipns/"+myself) {
		fmt.Fprintf(os.Stderr, "Can only write to your own filesystem (can only write to /ipns/%s/*, tried to write to %s)\n", myself, fullpath)
		os.Exit(2)
	}

	components := strings.SplitN(fullpath, "/", 4)

	return myself, components[3]
}

func encryptfile(path string, myparams *roaque.Params, revocList *roaque.RevocationList, newfile io.Reader) io.Reader {
	perm, err := starwave.ParsePermission(path, time.Now())
	handle(err)
	//encryptedkey, encfile, err := core.HybridStreamEncryptRevoc(rand.Reader, myparams, oaque.PrepareAttributeSet(myparams, perm.AttributeSet(starwave.KeyTypeDecryption)), revocList, newfile)
	encryptedkey, encfile, err := core.HybridStreamEncryptRevoc(rand.Reader, myparams, perm.AttributeSet(starwave.KeyTypeDecryption), revocList, newfile)
	handle(err)

	//tmp := encryptedkey.Marshal()
	//println(len(tmp))
	//println(string(tmp[1011]))
	newfile = io.MultiReader(starwave.MarshalIntoStream(perm, MarshalCompressed), bytes.NewReader(encryptedkey.Marshal(MarshalCompressed)), encfile)
	return newfile
}

func decryptfile(reader io.Reader, myparams *roaque.Params, mydk *roaque.PrivateKey) io.Reader {
	perm := new(starwave.Permission)
	err := starwave.UnmarshalFromStream(perm, reader, MarshalCompressed, MarshalChecked)
	handle(err)

	attrs := perm.AttributeSet(starwave.KeyTypeDecryption)
	decryptedreader, err := core.HybridStreamDecryptConcatenatedRevoc(reader, attrs, myparams, mydk)
	handle(err)

	return decryptedreader
}

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments...]\n", os.Args[0])
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]

	switch cmd {
	case "mkdir":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(3)
		}
		s := ipfs.NewLocalShell()
		myself, path := validatewrite(s, args[0])

		hash, err := s.NewObject("unixfs-dir")
		handle(err)
		fmt.Printf("Added directory: %s\n", hash)

		newroothash := addtofs(s, myself, path, hash, true)
		setnewroothash(s, newroothash, true)
	case "unlink":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(4)
		}
		s := ipfs.NewLocalShell()
		myself, path := validatewrite(s, args[0])

		newroothash, err := s.Patch("/ipns/"+myself, "rm-link", path)
		handle(err)
		fmt.Printf("Updated directory tree: %s\n", newroothash)

		setnewroothash(s, newroothash, true)
	case "ls":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(5)
		}
		s := ipfs.NewLocalShell()
		links, err := s.List(args[0])
		handle(err)

		for _, link := range links {
			terminator := ""
			if link.Type == ipfs.TDirectory {
				terminator = "/"
			}
			fmt.Printf("%s\t%s%s\t%v\n", link.Hash, link.Name, terminator, link.Size)
		}
	default:
		fmt.Fprintf(os.Stderr, "Invalid command %s\n", cmd)
		fallthrough
	case "-h":
		fallthrough
	case "-help":
		fallthrough
	case "--help":
		fallthrough
	case "help":
		fmt.Fprintln(os.Stderr, "Valid commands are: mkfile mkdir unlink ls cat register-fs")
		os.Exit(6)
	}
}
