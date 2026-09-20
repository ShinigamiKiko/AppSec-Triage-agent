package main

import (
	"log"
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

func main() {
	sock, err := net.Dial("unix", os.Getenv("SSH_AUTH_SOCK"))
	if err != nil {
		log.Fatal(err)
	}
	keys, err := agent.NewClient(sock).List()
	if err != nil {
		log.Fatal(err)
	}
	for _, key := range keys {
		log.Println(key.Comment)
	}
}
