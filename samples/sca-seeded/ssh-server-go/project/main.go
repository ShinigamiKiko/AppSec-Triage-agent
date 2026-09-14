package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"log"
	"net"

	"golang.org/x/crypto/ssh"
)

func main() {
	_, hostKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		log.Fatal(err)
	}
	signer, err := ssh.NewSignerFromKey(hostKey)
	if err != nil {
		log.Fatal(err)
	}

	config := &ssh.ServerConfig{
		PublicKeyCallback: func(meta ssh.ConnMetadata, key ssh.PublicKey) (*ssh.Permissions, error) {
			return &ssh.Permissions{Extensions: map[string]string{"pubkey-fp": ssh.FingerprintSHA256(key)}}, nil
		},
	}
	config.AddHostKey(signer)

	listener, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatal(err)
	}
	for {
		conn, err := listener.Accept()
		if err != nil {
			continue
		}
		go func() {
			_, chans, reqs, err := ssh.NewServerConn(conn, config)
			if err != nil {
				return
			}
			go ssh.DiscardRequests(reqs)
			for ch := range chans {
				ch.Reject(ssh.Prohibited, "no shells here")
			}
		}()
	}
}
