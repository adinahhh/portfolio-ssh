package audit

import (
	"fmt"
	"log"
	"os"
	"time"
)

type Logger struct {
	l *log.Logger
}

func NewLogger(path string) (*Logger, error) {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return nil, fmt.Errorf("failed to open audit log: %w", err)
	}
	return &Logger{l: log.New(f, "", 0)}, nil
}

func (a *Logger) log(event, ip, pubKey, detail string) {
	a.l.Printf("%s event=%s ip=%s pubkey=%q detail=%q",
		time.Now().UTC().Format(time.RFC3339),
		event, ip, pubKey, detail,
	)
}

func (a *Logger) Connected(ip string) {
	a.log("connected", ip, "", "")
}

func (a *Logger) AuthSuccess(ip, pubKey string, returning bool) {
	detail := "new user"
	if returning {
		detail = "returning user"
	}
	a.log("auth_success", ip, pubKey, detail)
}

func (a *Logger) AuthFailure(ip, pubKey, reason string) {
	a.log("auth_failure", ip, pubKey, reason)
}

func (a *Logger) Disconnected(ip string) {
	a.log("disconnected", ip, "", "")
}
