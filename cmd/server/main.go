package main

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"log"
	"net"
	"os"
	"sync"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/adinahhh/portfolio-ssh/cmd/internal/key"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/ratelimit"
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

	ln, err := net.Listen("tcp", ":2222")
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	// Allow 5 connection attempts per IP per minute, max 10 concurrent connections.
	limiter := ratelimit.New(5, time.Minute)
	connLimiter := ratelimit.NewConnLimiter(10)
	limited := &rateLimitedListener{Listener: ln, limiter: limiter, connLimiter: connLimiter}

	log.Println("SSH server listening on :2222")
	log.Fatal(srv.Serve(limited))
}

type rateLimitedListener struct {
	net.Listener
	limiter     *ratelimit.Limiter
	connLimiter *ratelimit.ConnLimiter
}

func (l *rateLimitedListener) Accept() (net.Conn, error) {
	for {
		conn, err := l.Listener.Accept()
		if err != nil {
			return nil, err
		}
		ip, _, _ := net.SplitHostPort(conn.RemoteAddr().String())
		if !l.limiter.Allow(ip) {
			log.Printf("rate limit exceeded for %s, dropping connection", ip)
			conn.Close()
			continue
		}
		if !l.connLimiter.Acquire() {
			log.Printf("connection limit reached, dropping connection from %s", ip)
			conn.Close()
			continue
		}
		return &trackedConn{Conn: conn, release: l.connLimiter.Release}, nil
	}
}

// trackedConn calls Release when the connection is closed, freeing the slot.
type trackedConn struct {
	net.Conn
	release func()
	once    sync.Once
}

func (c *trackedConn) Close() error {
	c.once.Do(c.release)
	return c.Conn.Close()
}

func loadOrGenerateHostKey(path string) (gossh.Signer, error) {
	if data, err := os.ReadFile(path); err == nil {
		block, _ := pem.Decode(data)
		if block != nil {
			return gossh.ParsePrivateKey(data)
		}
	}

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
