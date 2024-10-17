package ratelimit

import (
	"fmt"
	"sync"
	"time"
)

type RateLimiter struct {
	mu            sync.RWMutex
	requests      map[string][]time.Time
	windowSize    time.Duration
	maxRequests   int
	cleanupTicker *time.Ticker
}

func NewRateLimiter(windowSize time.Duration, maxRequests int) *RateLimiter {
	rl := &RateLimiter{
		requests:    make(map[string][]time.Time),
		windowSize:  windowSize,
		maxRequests: maxRequests,
	}

	// Start cleanup routine
	rl.cleanupTicker = time.NewTicker(time.Minute)
	go rl.cleanup()

	return rl
}

func (rl *RateLimiter) cleanup() {
	for range rl.cleanupTicker.C {
		rl.mu.Lock()
		now := time.Now()
		for ip, times := range rl.requests {
			var valid []time.Time
			for _, t := range times {
				if now.Sub(t) < rl.windowSize {
					valid = append(valid, t)
				}
			}
			if len(valid) == 0 {
				delete(rl.requests, ip)
			} else {
				rl.requests[ip] = valid
			}
		}
		rl.mu.Unlock()
	}
}

func (rl *RateLimiter) Allow(ip string) error {
	rl.mu.Lock()
	defer rl.mu.Unlock()

	now := time.Now()
	times := rl.requests[ip]

	// Remove old requests outside the window
	var valid []time.Time
	for _, t := range times {
		if now.Sub(t) < rl.windowSize {
			valid = append(valid, t)
		}
	}

	if len(valid) >= rl.maxRequests {
		return fmt.Errorf("rate limit exceeded. Maximum %d requests per %v", rl.maxRequests, rl.windowSize)
	}

	// Add new request time
	valid = append(valid, now)
	rl.requests[ip] = valid

	return nil
}

func (rl *RateLimiter) Close() {
	rl.cleanupTicker.Stop()
}
