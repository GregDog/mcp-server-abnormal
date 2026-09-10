package abnormal

import (
	"context"
	"encoding/base64"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

func encodeStdBase64(data []byte) string {
	return base64.StdEncoding.EncodeToString(data)
}

const defaultMaxEvidenceBytes = 10 * 1024 * 1024

func (c *client) doDownload(ctx context.Context, method, path string, query url.Values, maxBytes int64) (BinaryResponse, error) {
	if maxBytes <= 0 {
		maxBytes = defaultMaxEvidenceBytes
	}
	u, err := url.Parse(c.baseURL + path)
	if err != nil {
		return BinaryResponse{}, fmt.Errorf("parse url: %w", RedactError(err))
	}
	if len(query) > 0 {
		u.RawQuery = query.Encode()
	}

	req, err := http.NewRequestWithContext(ctx, method, u.String(), nil)
	if err != nil {
		return BinaryResponse{}, fmt.Errorf("create request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+c.token)
	if c.mockData {
		req.Header.Set("Mock-Data", "True")
	}

	resp, err := c.roundTrip(ctx, req)
	if err != nil {
		return BinaryResponse{}, err
	}
	defer resp.Body.Close()

	data, err := readLimitedBody(resp, maxBytes+1)
	if err != nil {
		return BinaryResponse{}, fmt.Errorf("read response: %w", err)
	}
	if int64(len(data)) > maxBytes {
		return BinaryResponse{}, fmt.Errorf("evidence payload exceeds max size (%d bytes)", maxBytes)
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		msg := strings.TrimSpace(string(data))
		if msg == "" {
			msg = resp.Status
		}
		return BinaryResponse{}, HTTPStatusError{StatusCode: resp.StatusCode, Message: msg}
	}

	ct := resp.Header.Get("Content-Type")
	if ct == "" {
		ct = "application/octet-stream"
	}
	return BinaryResponse{ContentType: ct, Data: data}, nil
}
