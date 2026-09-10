package abnormal

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"strings"
)

// APIError maps Abnormal API failures into a safe, redacted error.
func APIError(err error) error {
	if err == nil {
		return nil
	}
	switch {
	case errors.Is(err, context.Canceled):
		return fmt.Errorf("request canceled")
	case errors.Is(err, context.DeadlineExceeded):
		return fmt.Errorf("abnormal request timed out")
	}

	var httpErr HTTPStatusError
	if errors.As(err, &httpErr) {
		switch httpErr.StatusCode {
		case http.StatusForbidden:
			return fmt.Errorf("abnormal api: permission denied (HTTP 403); verify token scopes and tenant access (trial tenants may be read-only)")
		case http.StatusTooManyRequests:
			return fmt.Errorf("abnormal api: rate limited (HTTP 429); retries exhausted")
		case http.StatusNotFound:
			return fmt.Errorf("abnormal api: not found (HTTP 404)")
		default:
			if httpErr.StatusCode >= 500 {
				return fmt.Errorf("abnormal api: upstream error (HTTP %d): %s", httpErr.StatusCode, Redact(httpErr.Message))
			}
			return fmt.Errorf("abnormal api: %s", Redact(httpErr.Error()))
		}
	}

	msg := Redact(err.Error())
	if strings.Contains(strings.ToLower(msg), "read only") || strings.Contains(strings.ToLower(msg), "read-only") {
		return fmt.Errorf("abnormal api: write operation blocked (tenant may be read-only)")
	}
	return fmt.Errorf("abnormal api: %s", msg)
}
