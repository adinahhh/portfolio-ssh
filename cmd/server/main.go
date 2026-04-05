package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"log"
	"os"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/adinahhh/portfolio-ssh/cmd/internal/key"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/session"
)

const hostKeyPath = "cmd/internal/data/host_key"

func main() {
	signer, err := loadOrGenerateHostKey(hostKeyPath)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}

	handler := session.NewHandler(session.Config{
		AppPath:  "/Users/adinah/Projects/portfolio/.venv/bin/portfolio",
		KeyStore: key.NewFileStore("cmd/internal/data/known_keys.txt"),
	})

	srv := &gliderssh.Server{
		Addr:        ":2222",
		Handler:     handler,
		HostSigners: []gliderssh.Signer{signer},
	}

	log.Println("SSH server listening on :2222")
	log.Fatal(srv.ListenAndServe())
}

func loadOrGenerateHostKey(path string) (gossh.Signer, error) {
	// Load existing key.
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			return gossh.ParsePrivateKey(data)
		}
	}

	// Generate a new ed25519 key and persist it.
	_, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, err
	}

	block, err := gossh.MarshalPrivateKey(priv, "")
	if err != nil {
		return nil, err
	}

	_ = os.MkdirAll("cmd/internal/data", 0o700)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}

	return gossh.NewSignerFromKey(priv)
}
