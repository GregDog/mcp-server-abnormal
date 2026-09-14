package abnormal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestListDetection360Reports(t *testing.T) {
	var gotQuery string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode([]Detection360Case{{
			ID:          42,
			InquiryType: "FALSE_POSITIVE",
			Status:      "UNREVIEWED",
		}})
	})
	out, err := c.ListDetection360Reports(context.Background(), ListDetection360ReportsParams{
		InquiryType: "FALSE_POSITIVE",
		Start:       "2026-01-01T00:00:00Z",
		End:         "2026-02-01T00:00:00Z",
		Status:      []string{"UNREVIEWED", "RESOLVED"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "inquiry_type=FALSE_POSITIVE") {
		t.Fatalf("query: %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "status=UNREVIEWED") {
		t.Fatalf("query: %q", gotQuery)
	}
	if len(out) != 1 || out[0].ID != 42 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestSubmitDetection360Report(t *testing.T) {
	var gotBody Detection360SubmitRequest
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			t.Fatalf("method: %s", r.Method)
		}
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		w.WriteHeader(http.StatusAccepted)
	})
	err := c.SubmitDetection360Report(context.Background(), Detection360SubmitRequest{
		ReportType: "false-positive",
		PortalLink: "https://portal.abnormalsecurity.com/home/threat-center/remediation-history/123",
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotBody.ReportType != "false-positive" || gotBody.PortalLink == "" {
		t.Fatalf("body: %+v", gotBody)
	}
}
