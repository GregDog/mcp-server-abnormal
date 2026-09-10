package abnormal

import (
	"context"
	"math/rand"
	"net/http"
	"strconv"
	"time"
)

const (
	defaultMaxRetries = 2
	defaultRetryBase  = 500 * time.Millisecond
	defaultRetryMax   = 8 * time.Second
)

func retryableStatus(code int) bool {
	switch code {
	case http.StatusTooManyRequests, http.StatusBadGateway, http.StatusServiceUnavailable, http.StatusGatewayTimeout:
		return true
	default:
		return false
	}
}

func retryDelay(attempt int, retryAfter string) time.Duration {
	if retryAfter != "" {
		if secs, err := strconv.Atoi(retryAfter); err == nil && secs > 0 {
			return time.Duration(secs) * time.Second
		}
		if t, err := http.ParseTime(retryAfter); err == nil {
			d := time.Until(t)
			if d > 0 {
				return d
			}
		}
	}
	// attempt is 1-indexed for the retry (first retry = attempt 1).
	delay := defaultRetryBase * time.Duration(1<<uint(attempt-1))
	if delay > defaultRetryMax {
		delay = defaultRetryMax
	}
	jitter := time.Duration(rand.Int63n(int64(delay / 4)))
	return delay + jitter
}

func waitForRetry(ctx context.Context, attempt int, retryAfter string) error {
	timer := time.NewTimer(retryDelay(attempt, retryAfter))
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}
