package main

import (
	"log"

	gliderssh "github.com/gliderlabs/ssh"

	"github.com/adinahhh/portfolio-ssh/cmd/internal/key"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/session"
)

func main() {
	handler := session.NewHandler(session.Config{
		AppPath:  "/Users/adinah/Projects/portfolio/.venv/bin/portfolio",
		KeyStore: key.NewFileStore("data/known_keys.txt"),
	})

	srv := &gliderssh.Server{
		Addr:    ":2222",
		Handler: handler,
	}

	log.Println("SSH server listening on :2222")
	log.Fatal(srv.ListenAndServe())
}
