package ratelimit

import (
	"sync"
	"time"
)

// Limiter tracks connection attempts per IP using a sliding window.
type Limiter struct {
	mu       sync.Mutex
	attempts map[string][]time.Time
	max      int
	window   time.Duration
}

func New(max int, window time.Duration) *Limiter {
	l := &Limiter{
		attempts: make(map[string][]time.Time),
		max:      max,
		window:   window,
	}
	go l.cleanup()
	return l
}

// Allow returns true if the IP is within the rate limit.
func (l *Limiter) Allow(ip string) bool {
	l.mu.Lock()
	defer l.mu.Unlock()

	now := time.Now()
	cutoff := now.Add(-l.window)

	var recent []time.Time
	for _, t := range l.attempts[ip] {
		if t.After(cutoff) {
			recent = append(recent, t)
		}
	}

	if len(recent) >= l.max {
		l.attempts[ip] = recent
		return false
	}

	l.attempts[ip] = append(recent, now)
	return true
}

// cleanup periodically removes expired entries to prevent unbounded memory growth.
func (l *Limiter) cleanup() {
	ticker := time.NewTicker(time.Minute)
	defer ticker.Stop()
	for range ticker.C {
		l.mu.Lock()
		cutoff := time.Now().Add(-l.window)
		for ip, times := range l.attempts {
			var recent []time.Time
			for _, t := range times {
				if t.After(cutoff) {
					recent = append(recent, t)
				}
			}
			if len(recent) == 0 {
				delete(l.attempts, ip)
			} else {
				l.attempts[ip] = recent
			}
		}
		l.mu.Unlock()
	}
}
