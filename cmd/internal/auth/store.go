package auth

import (
	"errors"
	"sync"
	"time"
)

// ChallengeStore issues and tracks challenges, ensuring each is used at most once.
type ChallengeStore struct {
	mu         sync.Mutex
	challenges map[string]time.Time // value -> expiry
	ttl        time.Duration
}

func NewChallengeStore(ttl time.Duration) *ChallengeStore {
	cs := &ChallengeStore{
		challenges: make(map[string]time.Time),
		ttl:        ttl,
	}
	go cs.cleanup()
	return cs
}

// Issue generates a new challenge, registers it, and returns it.
func (cs *ChallengeStore) Issue() (Challenge, error) {
	c, err := NewChallenge(cs.ttl)
	if err != nil {
		return Challenge{}, err
	}
	cs.mu.Lock()
	cs.challenges[c.Value] = c.ExpiresAt
	cs.mu.Unlock()
	return c, nil
}

// Consume marks a challenge as used. Returns an error if it is unknown,
// expired, or has already been consumed.
func (cs *ChallengeStore) Consume(value string) error {
	cs.mu.Lock()
	defer cs.mu.Unlock()

	expiry, ok := cs.challenges[value]
	if !ok {
		return errors.New("unknown or already used challenge")
	}
	delete(cs.challenges, value)
	if time.Now().After(expiry) {
		return errors.New("challenge expired")
	}
	return nil
}

// cleanup removes expired challenges periodically.
func (cs *ChallengeStore) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		cs.mu.Lock()
		now := time.Now()
		for v, expiry := range cs.challenges {
			if now.After(expiry) {
				delete(cs.challenges, v)
			}
		}
		cs.mu.Unlock()
	}
}
