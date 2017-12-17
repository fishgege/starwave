package main

import (
	"fmt"
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

func main() {
	if len(os.Args) < 2 {
		fmt.Fprintf(os.Stderr, "Usage: %s <command> [arguments...]\n", os.Args[0])
		os.Exit(1)
	}
	cmd := os.Args[1]
	args := os.Args[2:]
	switch cmd {
	case "add":
		if len(args) != 1 && len(args) != 2 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <dst> [<src>]\n", os.Args[0], cmd)
			fmt.Fprintln(os.Stderr, "Reads from stdin if no <src> is provided")
			os.Exit(2)
		}
		s := ipfs.NewLocalShell()

		idout, err := s.ID()
		handle(err)

		myself := idout.ID

		components := strings.Split(args[0], "/")

		if components[2] != myself {
			fmt.Fprintf(os.Stderr, "Can only write to your own filesystem (you are %s, tried to write to filesystem of %s)\n", myself, components[2])
			os.Exit(2)
		}

		hash, err := s.Add(strings.NewReader(args[1]))
		handle(err)

		fmt.Printf("Added file: %s\n", hash)

		newroothash, err := s.Patch(strings.Join(components[:3], "/"), "add-link", strings.Join(components[3:], "/"), "/ipfs/"+hash)
		handle(err)

		fmt.Printf("Updated directory tree: %s\n", newroothash)

		err = s.Publish("", newroothash)
		handle(err)

		fmt.Println("Published new root")
	case "unlink":
		if len(args) != 1 {
			fmt.Fprintf(os.Stderr, "Usage: %s %s <target>\n", os.Args[0], cmd)
			os.Exit(3)
		}
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
		fmt.Fprintln(os.Stderr, "Valid commands are: add unlink ls cat")
		os.Exit(6)
	}
}
