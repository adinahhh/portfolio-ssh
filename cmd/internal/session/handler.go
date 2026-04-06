package session

import (
	"errors"
	"fmt"
	"io"
	"net"
	"os/exec"
	"strings"
	"time"

	"github.com/creack/pty"
	gliderssh "github.com/gliderlabs/ssh"

	"github.com/adinahhh/portfolio-ssh/cmd/internal/audit"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/auth"
	"github.com/adinahhh/portfolio-ssh/cmd/internal/key"
)

const (
	defaultChallengeTTL   = 2 * time.Minute
	defaultSessionTimeout = 5 * time.Minute
)

type Config struct {
	AppPath        string
	KeyStore       key.Store
	ChallengeStore *auth.ChallengeStore
	ChallengeTTL   time.Duration
	AuditLogger    *audit.Logger
}

func NewHandler(cfg Config) func(gliderssh.Session) {
	if cfg.ChallengeTTL == 0 {
		cfg.ChallengeTTL = defaultChallengeTTL
	}
	if cfg.ChallengeStore == nil {
		cfg.ChallengeStore = auth.NewChallengeStore(cfg.ChallengeTTL)
	}

	return func(s gliderssh.Session) {
		ip, _, _ := net.SplitHostPort(s.RemoteAddr().String())

		if cfg.AuditLogger != nil {
			cfg.AuditLogger.Connected(ip)
			defer cfg.AuditLogger.Disconnected(ip)
		}

		ptyReq, winCh, ok := s.Pty()
		if !ok {
			io.WriteString(s, "A TTY is required.\r\n")
			return
		}

		// Enforce a session-level timeout for the auth phase.
		timeout := time.AfterFunc(defaultSessionTimeout, func() {
			io.WriteString(s, "\r\nSession timed out.\r\n")
			s.Close()
		})
		defer timeout.Stop()

		if err := runAuth(s, cfg); err != nil {
			if cfg.AuditLogger != nil {
				cfg.AuditLogger.AuthFailure(ip, "", err.Error())
			}
			fmt.Fprintf(s, "\r\nAuthentication failed: %v\r\n", err)
			return
		}

		timeout.Stop()

		cmd := exec.Command(cfg.AppPath)

		ptmx, err := pty.Start(cmd)
		if err != nil {
			fmt.Fprintf(s, "Failed to start portfolio app: %v\r\n", err)
			return
		}
		defer ptmx.Close()

		_ = pty.Setsize(ptmx, &pty.Winsize{
			Rows: uint16(ptyReq.Window.Height),
			Cols: uint16(ptyReq.Window.Width),
		})

		go func() {
			for win := range winCh {
				_ = pty.Setsize(ptmx, &pty.Winsize{
					Rows: uint16(win.Height),
					Cols: uint16(win.Width),
				})
			}
		}()

		go func() {
			_, _ = io.Copy(ptmx, s)
		}()

		_, _ = io.Copy(s, ptmx)
		_ = cmd.Wait()
	}
}

func runAuth(s gliderssh.Session, cfg Config) error {
	ip, _, _ := net.SplitHostPort(s.RemoteAddr().String())

	io.WriteString(s, "\r\nWelcome! To continue, please paste your SSH public key below.\r\n\r\n"+
		"If you don't have one yet, open another terminal and run:\r\n"+
		"    ssh-keygen -t ed25519\r\n\r\n"+
		"Then copy your public key by running:\r\n"+
		"    cat ~/.ssh/id_ed25519.pub\r\n\r\n"+
		"And paste it here:\r\n> ")

	pubKeyLine, err := readLine(s)
	if err != nil {
		return fmt.Errorf("failed to read public key: %w", err)
	}
	pubKeyLine = strings.TrimSpace(pubKeyLine)
	if pubKeyLine == "" {
		return errors.New("empty public key")
	}

	// Returning users bypass the challenge, go straight to tui
	if cfg.KeyStore != nil {
		known, err := cfg.KeyStore.Has(pubKeyLine)
		if err != nil {
			return fmt.Errorf("failed to check key store: %w", err)
		}
		if known {
			if cfg.AuditLogger != nil {
				cfg.AuditLogger.AuthSuccess(ip, pubKeyLine, true)
			}
			io.WriteString(s, "\r\nWelcome back! Launching my portfolio now...\r\n\r\n")
			return nil
		}
	}

	challenge, err := cfg.ChallengeStore.Issue()
	if err != nil {
		return fmt.Errorf("failed to generate a challenge: %w", err)
	}

	fmt.Fprintf(s,
		"\r\nTo verify you own this public key, please sign the challenge below using your private key.\r\n\r\n"+
			"Your private key never leaves your machine. This step only generates a signature and is safe to share.\r\n\r\n"+
			"Open a second terminal tab and paste this command exactly as shown:\r\n\r\n"+
			"    printf '%%s' '%s' | ssh-keygen -Y sign -f ~/.ssh/id_ed25519 -n file\r\n\r\n"+
			"Then paste the full signature block below, including:\r\n"+
			"    -----BEGIN SSH SIGNATURE-----\r\n"+
			"    -----END SSH SIGNATURE-----\r\n\r\n"+
			"> ",
		challenge.Value,
	)

	// Read lines until the closing PEM boundary.
	var sigLines []string
	for {
		line, err := readLine(s)
		if err != nil {
			return fmt.Errorf("failed to read signature: %w", err)
		}
		sigLines = append(sigLines, line)
		if strings.TrimSpace(line) == "-----END SSH SIGNATURE-----" {
			break
		}
	}

	if len(sigLines) == 0 {
		return errors.New("no signature provided")
	}

	if err := cfg.ChallengeStore.Consume(challenge.Value); err != nil {
		return err
	}

	sigBlock := strings.Join(sigLines, "\n")
	if err := auth.VerifySignature(pubKeyLine, "file", challenge.Value, sigBlock); err != nil {
		return err
	}

	if cfg.KeyStore != nil {
		_ = cfg.KeyStore.Add(pubKeyLine)
	}

	if cfg.AuditLogger != nil {
		cfg.AuditLogger.AuthSuccess(ip, pubKeyLine, false)
	}

	io.WriteString(s, "\r\nVerification successful! Launching portfolio...\r\n\r\n")
	return nil
}

// readLine reads one line from rw, echoing each character back so the user
// can see their input. The client terminal is in raw mode during the auth
// phase (no subprocess pty running yet), so the server must handle echo.
func readLine(rw io.ReadWriter) (string, error) {
	var line []byte
	buf := make([]byte, 1)
	for {
		if _, err := rw.Read(buf); err != nil {
			return "", err
		}
		switch buf[0] {
		case '\r', '\n':
			io.WriteString(rw, "\r\n")
			return string(line), nil
		case 0x7f, 0x08: // DEL / backspace
			if len(line) > 0 {
				line = line[:len(line)-1]
				io.WriteString(rw, "\b \b")
			}
		case 0x03: // Ctrl-C
			return "", errors.New("interrupted")
		default:
			if buf[0] >= 0x20 { // printable ASCII / UTF-8 continuation bytes
				line = append(line, buf[0])
				rw.Write(buf[:1])
			}
		}
	}
}
