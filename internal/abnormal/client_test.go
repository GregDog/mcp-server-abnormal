package abnormal

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

func TestListThreatsSendsFilter(t *testing.T) {
	var gotAuth string
	var gotFilter string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotFilter = r.URL.Query().Get("filter")
		_ = json.NewEncoder(w).Encode(PaginatedThreats{
			Threats:    []ThreatRef{{ThreatID: "t1"}},
			PageNumber: 1,
		})
	}))
	defer srv.Close()

	c, err := New(config.Config{
		APIToken: "test-token",
		BaseURL:  srv.URL + "/v1",
	})
	if err != nil {
		t.Fatal(err)
	}
	wantFilter := "receivedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z"
	_, err = c.ListThreats(context.Background(), ListThreatsParams{
		Filter:     FormatTimeFilter("receivedTime", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z"),
		PageSize:   20,
		PageNumber: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotAuth != "Bearer test-token" {
		t.Fatalf("auth: %q", gotAuth)
	}
	if gotFilter != wantFilter {
		t.Fatalf("filter: %q", gotFilter)
	}
}

func TestSearchMessagesRateLimit(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("slow down"))
	}))
	defer srv.Close()

	c, err := New(config.Config{APIToken: "t", BaseURL: srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.SearchMessages(context.Background(), SearchRequest{
		Source: "abnormal",
		Filters: SearchFilters{
			StartTime: "2024-01-01T00:00:00Z",
			EndTime:   "2024-01-02T00:00:00Z",
		},
	}, 20, 1)
	if err == nil || !strings.Contains(err.Error(), "429") {
		t.Fatalf("expected 429 error, got %v", err)
	}
}

func TestFormatTimeFilter(t *testing.T) {
	got := FormatTimeFilter("receivedTime", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	want := "receivedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z"
	if got != want {
		t.Fatalf("got %q", got)
	}
	gotMailbox := FormatTimeFilter("lastReportedTime", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	wantMailbox := "lastReportedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z"
	if gotMailbox != wantMailbox {
		t.Fatalf("mailbox filter: %q", gotMailbox)
	}
}
