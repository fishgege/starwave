package main

import (
	"fmt"
	"io"
	"os"
	"strings"

	ipfs "github.com/ipfs/go-ipfs-api"
)

func handle(err error) {
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(100)
	}
}

func addtofs(s *ipfs.Shell, nodeid string, path string, filehash string) string {
	newroothash, err := s.Patch("/ipns/"+nodeid, "add-link", path, "/ipfs/"+filehash)
	handle(err)

	fmt.Printf("Updated directory tree: %s\n", newroothash)
	return newroothash
}

func setnewroothash(s *ipfs.Shell, newroothash string) {
	err := s.Publish("", newroothash)
	handle(err)

	fmt.Println("Published new root")
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments...]\n", os.Args[0])
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
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

		hash, err := s.Add(newfile)
		handle(err)
		fmt.Printf("Added file: %s\n", hash)

		newroothash := addtofs(s, myself, path, hash)
		setnewroothash(s, newroothash)
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

		newroothash := addtofs(s, myself, path, hash)
		setnewroothash(s, newroothash)
	case "unlink":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(3)
		}
		s := ipfs.NewLocalShell()
		myself, path := validatewrite(s, args[0])

		newroothash, err := s.Patch("/ipns/"+myself, "rm-link", path)
		handle(err)
		fmt.Printf("Updated directory tree: %s\n", newroothash)

		setnewroothash(s, newroothash)
	case "ls":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(4)
		}
	case "cat":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(5)
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
		fmt.Fprintln(os.Stderr, "Valid commands are: mkfile mkdir unlink ls cat")
		os.Exit(6)
	}
}
