package ratelimit

// ConnLimiter caps the number of concurrent active connections using a semaphore.
type ConnLimiter struct {
	sem chan struct{}
}

func NewConnLimiter(max int) *ConnLimiter {
	return &ConnLimiter{sem: make(chan struct{}, max)}
}

// Acquire attempts to claim a connection slot. Returns false if the limit is reached.
func (c *ConnLimiter) Acquire() bool {
	select {
	case c.sem <- struct{}{}:
		return true
	default:
		return false
	}
}

// Release frees a connection slot.
func (c *ConnLimiter) Release() {
	<-c.sem
}
