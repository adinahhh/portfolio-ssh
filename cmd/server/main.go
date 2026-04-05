package main

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"encoding/pem"
	"log"
	"net"
	"os"
	"os/signal"
	"sync"
	"syscall"
	"time"

	gliderssh "github.com/gliderlabs/ssh"
	gossh "golang.org/x/crypto/ssh"

	"github.com/adinahhh/portfolio-ssh/cmd/internal/audit"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/key"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/ratelimit"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/session"
)

func getenv(key, fallback string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return fallback
}

func main() {
	appPath := getenv("PORTFOLIO_APP_PATH", "/Users/adinah/Projects/portfolio/.venv/bin/portfolio")
	dataDir := getenv("PORTFOLIO_DATA_DIR", "cmd/internal/data")
	addr := getenv("PORTFOLIO_ADDR", ":2222")

	hostKeyPath := dataDir + "/host_key"
	knownKeysPath := dataDir + "/known_keys.txt"
	auditLogPath := dataDir + "/audit.log"

	signer, err := loadOrGenerateHostKey(hostKeyPath, dataDir)
	if err != nil {
		log.Fatalf("host key: %v", err)
	}

	auditLogger, err := audit.NewLogger(auditLogPath)
	if err != nil {
		log.Fatalf("audit logger: %v", err)
	}

	handler := session.NewHandler(session.Config{
		AppPath:     appPath,
		KeyStore:    key.NewFileStore(knownKeysPath),
		AuditLogger: auditLogger,
	})

	srv := &gliderssh.Server{
		Addr:        addr,
		Handler:     handler,
		HostSigners: []gliderssh.Signer{signer},
	}

	ln, err := net.Listen("tcp", addr)
	if err != nil {
		log.Fatalf("listen: %v", err)
	}

	// Allow 5 connection attempts per IP per minute, max 10 concurrent connections.
	limiter := ratelimit.New(5, time.Minute)
	connLimiter := ratelimit.NewConnLimiter(10)
	limited := &rateLimitedListener{Listener: ln, limiter: limiter, connLimiter: connLimiter}

	// Start serving in the background
	serveErr := make(chan error, 1)
	go func() {
		log.Printf("SSH server listening on port %s", addr)
		serveErr <- srv.Serve(limited)
	}()

	// Wait for SIGINT (Ctrl + C) or SIGTERM (systemd stop) to gracefully shut down the server
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	select {
	case err := <-serveErr:
		log.Fatalf("server error: %v", err)
	case <-ctx.Done():
		log.Println("shutting down server, waiting for active sessions to finish...")
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
		defer cancel()
		if err := srv.Shutdown(shutdownCtx); err != nil {
			log.Printf("shutdown error: %v", err)
		}
		log.Println("server stopped")
	}
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

func loadOrGenerateHostKey(path, dataDir string) (gossh.Signer, error) {
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

	_ = os.MkdirAll(dataDir, 0o700)
	if err := os.WriteFile(path, pem.EncodeToMemory(block), 0o600); err != nil {
		return nil, err
	}

	return gossh.NewSignerFromKey(priv)
}
