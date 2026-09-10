package abnormal

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"net/http"
)

func (c *client) roundTrip(ctx context.Context, req *http.Request) (*http.Response, error) {
	var bodyBytes []byte
	if req.Body != nil {
		b, err := io.ReadAll(req.Body)
		if err != nil {
			return nil, RedactError(err)
		}
		_ = req.Body.Close()
		bodyBytes = b
	}

	var lastRetryAfter string
	for attempt := 0; attempt <= c.maxRetries; attempt++ {
		if attempt > 0 {
			if err := waitForRetry(ctx, attempt, lastRetryAfter); err != nil {
				return nil, RedactError(err)
			}
		}

		cloned := req.Clone(ctx)
		if len(bodyBytes) > 0 {
			cloned.Body = io.NopCloser(bytes.NewReader(bodyBytes))
			cloned.ContentLength = int64(len(bodyBytes))
		}

		resp, err := c.http.Do(cloned)
		if err != nil {
			if attempt < c.maxRetries {
				continue
			}
			return nil, RedactError(err)
		}

		if retryableStatus(resp.StatusCode) && attempt < c.maxRetries {
			lastRetryAfter = resp.Header.Get("Retry-After")
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
			continue
		}
		return resp, nil
	}
	return nil, fmt.Errorf("abnormal api: retries exhausted")
}

func readLimitedBody(resp *http.Response, limit int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(resp.Body, limit))
	if err != nil {
		return nil, err
	}
	return data, nil
}
