package abnormal

import (
	"context"
	"encoding/json"
	"net/http"
	"strings"
	"testing"
)

func TestListAuditLogs(t *testing.T) {
	var gotQuery string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_ = json.NewEncoder(w).Encode(AuditLogResponse{
			AuditLogs: []AuditLog{{
				Timestamp:  "2026-01-01T00:00:00Z",
				Category:   "threat_log",
				Action:     "view_message_content",
				Status:     "SUCCESS",
				SourceIP:   "1.2.3.4",
				TenantName: "Example",
				User:       AuditLogUser{Email: "analyst@example.com"},
			}},
			PageNumber:     1,
			NextPageNumber: 2,
		})
	})
	filter := FormatTimeFilter("timestamp", "2026-01-01T00:00:00Z", "2026-01-02T00:00:00Z")
	out, err := c.ListAuditLogs(context.Background(), ListAuditLogsParams{
		Filter:     filter,
		Action:     "view_message_content",
		Category:   "threat_log",
		Status:     "SUCCESS",
		SourceIP:   "1.2.3.4",
		PageSize:   20,
		PageNumber: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(gotQuery, "filter=") {
		t.Fatalf("query: %q", gotQuery)
	}
	if !strings.Contains(gotQuery, "action=view_message_content") {
		t.Fatalf("query: %q", gotQuery)
	}
	if len(out.AuditLogs) != 1 || out.AuditLogs[0].User.Email != "analyst@example.com" {
		t.Fatalf("unexpected: %+v", out)
	}
}
