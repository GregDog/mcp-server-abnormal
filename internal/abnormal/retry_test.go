package abnormal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"sync/atomic"
	"testing"
	"time"

	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

func TestRetryOn429ThenSuccess(t *testing.T) {
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if calls.Add(1) == 1 {
			w.Header().Set("Retry-After", "0")
			w.WriteHeader(http.StatusTooManyRequests)
			return
		}
		_ = json.NewEncoder(w).Encode(PaginatedThreats{Threats: []ThreatRef{{ThreatID: "t1"}}})
	}))
	t.Cleanup(srv.Close)

	c, err := New(config.Config{APIToken: "test-token", BaseURL: srv.URL + "/v1", HTTPMaxRetries: 2})
	if err != nil {
		t.Fatal(err)
	}
	out, err := c.ListThreats(context.Background(), ListThreatsParams{PageSize: 1, PageNumber: 1})
	if err != nil {
		t.Fatal(err)
	}
	if calls.Load() < 2 {
		t.Fatalf("expected retry, calls=%d", calls.Load())
	}
	if len(out.Threats) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestHTTPStatusErrorMapsToAPIError(t *testing.T) {
	err := APIError(HTTPStatusError{StatusCode: 403, Message: "forbidden"})
	if err == nil || err.Error() == "" {
		t.Fatal("expected error")
	}
	want := "abnormal api: permission denied (HTTP 403); verify token scopes and tenant access (trial tenants may be read-only)"
	if err.Error() != want {
		t.Fatalf("got %q", err.Error())
	}
}

func TestRetryDelayRespectsRetryAfterSeconds(t *testing.T) {
	d := retryDelay(1, "2")
	if d < 2*time.Second {
		t.Fatalf("expected at least 2s, got %v", d)
	}
}
