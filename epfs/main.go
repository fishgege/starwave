package main

import (
	"bytes"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/immesys/bw2bind"
	ipfs "github.com/ipfs/go-ipfs-api"
	"github.com/ucbrise/starwave/core"
	"github.com/ucbrise/starwave/crypto/oaque"
	"github.com/ucbrise/starwave/starwave"
	"github.com/ucbrise/starwave/swbind"
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

func encryptfile(path string, myparams *oaque.Params, newfile io.Reader) io.Reader {
	perm, err := starwave.ParsePermission(path, time.Now())
	handle(err)
	encryptedkey, encfile, err := core.HybridStreamEncrypt(rand.Reader, myparams, oaque.PrepareAttributeSet(myparams, perm.AttributeSet(starwave.KeyTypeDecryption)), newfile)
	handle(err)

	newfile = io.MultiReader(starwave.MarshalIntoStream(perm), bytes.NewReader(encryptedkey.Marshal()), encfile)
	return newfile
}

func obtainkey(perm *starwave.Permission, swc *swbind.SWClient, namespace string, myvk string, myhd *starwave.HierarchyDescriptor, verbose bool) (*oaque.Params, *oaque.PrivateKey) {
	var decryptionkey *oaque.PrivateKey
	var params *oaque.Params
	var err error
	if namespace == myvk {
		decryptionkey = swc.GetNamespaceDecryptionKey().Key
		params = myhd.Params
	} else {
		var namespacekey *starwave.DecryptionKey
		namespacekey, err = swc.ObtainKey(namespace, perm, starwave.KeyTypeDecryption)
		handle(err)
		if namespacekey == nil {
			fmt.Fprintf(os.Stderr, "Could not obtain decryption key for %s and %s\n", perm.URI.String(), perm.Time.String())
			os.Exit(8)
		}
		decryptionkey = namespacekey.Key
		params = namespacekey.Hierarchy.Params
		if verbose {
			fmt.Fprintf(os.Stderr, "Obtained decryption key for %s and %s\n", namespacekey.Permissions.URI.String(), namespacekey.Permissions.Time.String())
		}
	}

	return params, decryptionkey
}

// In case the application has the key cached
func decryptfilewithkey(reader io.Reader, params *oaque.Params, decryptionkey *oaque.PrivateKey) io.Reader {
	perm := new(starwave.Permission)
	err := starwave.UnmarshalFromStream(perm, reader)
	handle(err)

	decryptionkey = oaque.NonDelegableKey(params, decryptionkey, perm.AttributeSet(starwave.KeyTypeDecryption))

	decryptedreader, err := core.HybridStreamDecryptConcatenated(reader, decryptionkey)
	handle(err)

	return decryptedreader
}

func decryptfile(reader io.Reader, swc *swbind.SWClient, namespace string, myvk string, myhd *starwave.HierarchyDescriptor, verbose bool) io.Reader {
	perm := new(starwave.Permission)
	err := starwave.UnmarshalFromStream(perm, reader)
	handle(err)

	var decryptionkey *oaque.PrivateKey
	var params *oaque.Params
	if namespace == myvk {
		decryptionkey = swc.GetNamespaceDecryptionKey().Key
		params = myhd.Params
	} else {
		var namespacekey *starwave.DecryptionKey
		namespacekey, err = swc.ObtainKey(namespace, perm, starwave.KeyTypeDecryption)
		handle(err)
		if namespacekey == nil {
			fmt.Fprintf(os.Stderr, "Could not obtain decryption key for %s and %s\n", perm.URI.String(), perm.Time.String())
			os.Exit(8)
		}
		decryptionkey = namespacekey.Key
		params = namespacekey.Hierarchy.Params
		if verbose {
			fmt.Fprintf(os.Stderr, "Obtained decryption key for %s and %s\n", namespacekey.Permissions.URI.String(), namespacekey.Permissions.Time.String())
		}
	}

	decryptionkey = oaque.NonDelegableKey(params, decryptionkey, perm.AttributeSet(starwave.KeyTypeDecryption))

	decryptedreader, err := core.HybridStreamDecryptConcatenated(reader, decryptionkey)
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

	bw2bind.SilenceLog()
	swc := swbind.ConnectOrExit("")
	myvk := swc.SetEntityFromEnvironOrExit()
	myhd := swbind.HierarchyDescriptorFromEntity(swc.GetEntity())
	myparams := myhd.Params

	switch cmd {
	case "mkfile":
		if len(args) != 1 && len(args) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <dst> [<src>]\n", os.Args[0], cmd)
			fmt.Fprintln(os.Stderr, "Reads from stdin if no <src> is provided")
			os.Exit(2)
		}
		s := ipfs.NewLocalShell()
		myself, path := validatewrite(s, args[0])

		var newfile io.Reader
		if len(args) == 2 {
			newfile = strings.NewReader(args[1])
		} else {
			newfile = os.Stdin
		}

		newfile = encryptfile(path, myparams, newfile)

		hash, err := s.Add(newfile)
		handle(err)
		fmt.Printf("Added file: %s\n", hash)

		newroothash := addtofs(s, myself, path, hash, true)
		setnewroothash(s, newroothash, true)
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
	case "cat":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(6)
		}
		s := ipfs.NewLocalShell()
		if !strings.HasPrefix(args[0], "/ipns/") {
			fmt.Fprintln(os.Stderr, "Can only interface with full paths (/ipns/*)")
			os.Exit(2)
		}
		nodeidstring := strings.SplitN(args[0], "/", 4)[2]
		enthash, zero, err := swc.ResolveLongAlias(nodeidstring[:32])
		handle(err)
		if zero {
			fmt.Fprintf(os.Stderr, "Could not resolve alias %s in BW2\n", nodeidstring[:32])
			os.Exit(3)
		}
		namespace := base64.URLEncoding.EncodeToString(enthash)
		fmt.Fprintf(os.Stderr, "BW2 Namespace is %s\n", namespace)

		reader, err := s.Cat(args[0])
		handle(err)
		defer reader.Close()

		decryptedreader := decryptfile(reader, swc, namespace, myvk, myhd, true)

		var buf [4096]byte
		for err == nil {
			var n int
			n, err = io.ReadFull(decryptedreader, buf[:])
			os.Stdout.Write(buf[:n])
		}
		if err != io.EOF && err != io.ErrUnexpectedEOF {
			fmt.Println(err)
		}
	case "register-fs":
		if len(args) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <base64-encoded STARWAVE entity VK> <STARWAVE bankroll>\n", os.Args[0], cmd)
			os.Exit(7)
		}
		swc.SetEntityFileOrExit(args[1])

		s := ipfs.NewLocalShell()
		nodeid, err := s.ID()
		handle(err)

		aliaskey := []byte(nodeid.ID[:32])
		aliasval, err := base64.URLEncoding.DecodeString(args[0])
		handle(err)
		err = swc.CreateLongAlias(0, aliaskey, aliasval)
		handle(err)
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
