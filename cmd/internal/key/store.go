package key

import (
	"bufio"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
)

type Store interface {
	Has(pubKeyLine string) (bool, error)
	Add(pubKeyLine string) error
}

type FileStore struct {
	path string
	mu   sync.Mutex
}

func NewFileStore(path string) *FileStore {
	_ = os.MkdirAll(filepath.Dir(path), 0o700)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND, 0o600)
	if err == nil {
		f.Close()
	}
	return &FileStore{path: path}
}

func (s *FileStore) Has(pubKeyLine string) (bool, error) {
	pubKeyLine = strings.TrimSpace(pubKeyLine)
	if pubKeyLine == "" {
		return false, errors.New("empty public key")
	}

	f, err := os.Open(s.path)
	if err != nil {
		return false, err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for sc.Scan() {
		if strings.TrimSpace(sc.Text()) == pubKeyLine {
			return true, nil
		}
	}
	if err := sc.Err(); err != nil {
		return false, err
	}
	return false, nil
}

func (s *FileStore) Add(pubKeyLine string) error {
	pubKeyLine = strings.TrimSpace(pubKeyLine)
	if pubKeyLine == "" {
		return errors.New("empty public key")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	has, err := s.Has(pubKeyLine)
	if err != nil {
		return err
	}
	if has {
		return nil
	}

	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()

	_, err = f.WriteString(pubKeyLine + "\n")
	return err
}
