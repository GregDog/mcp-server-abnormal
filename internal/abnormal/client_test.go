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

func testClient(t *testing.T, handler http.HandlerFunc) API {
	srv := httptest.NewServer(handler)
	t.Cleanup(srv.Close)
	c, err := New(config.Config{APIToken: "test-token", BaseURL: srv.URL + "/v1"})
	if err != nil {
		t.Fatal(err)
	}
	return c
}

func TestListThreatsSendsFilter(t *testing.T) {
	var gotAuth string
	var gotFilter string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotAuth = r.Header.Get("Authorization")
		gotFilter = r.URL.Query().Get("filter")
		_ = json.NewEncoder(w).Encode(PaginatedThreats{
			Threats:    []ThreatRef{{ThreatID: "t1"}},
			PageNumber: 1,
		})
	})
	wantFilter := "receivedTime gte 2024-01-01T00:00:00Z lte 2024-01-02T00:00:00Z"
	_, err := c.ListThreats(context.Background(), ListThreatsParams{
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

func TestGetThreat(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(ThreatDetails{
			ThreatID:       "threat-1",
			RecipientCount: 2,
			Messages:       []ThreatMessage{{AbxMessageID: 99, Subject: "hi"}},
		})
	})
	out, err := c.GetThreat(context.Background(), "threat-1", 50, 1)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/threats/threat-1" {
		t.Fatalf("path: %q", gotPath)
	}
	if out.ThreatID != "threat-1" || len(out.Messages) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestSearchMessages(t *testing.T) {
	var gotMethod string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		_ = json.NewEncoder(w).Encode(SearchResponse{
			Results:    []SearchResult{{Subject: strPtr("hello")}},
			Total:      1,
			PageNumber: 1,
			PageSize:   5,
		})
	})
	out, err := c.SearchMessages(context.Background(), SearchRequest{
		Source: "abnormal",
		Filters: SearchFilters{
			StartTime: "2024-01-01T00:00:00Z",
			EndTime:   "2024-01-02T00:00:00Z",
		},
	}, 5, 1)
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost {
		t.Fatalf("method: %q", gotMethod)
	}
	if len(out.Results) != 1 || out.Total != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestSearchMessagesRateLimit(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusTooManyRequests)
		_, _ = w.Write([]byte("slow down"))
	})
	_, err := c.SearchMessages(context.Background(), SearchRequest{
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

func TestListSearchActivities(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(ActivitiesResponse{
			Activities: []ActivityLogEntry{{ActivityID: 7, Action: "delete", Status: "completed"}},
			Total:      1,
			PageNumber: 1,
			PageSize:   20,
		})
	})
	out, err := c.ListSearchActivities(context.Background(), ListActivitiesParams{PageSize: 20, PageNumber: 1})
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/search/activities" {
		t.Fatalf("path: %q", gotPath)
	}
	if len(out.Activities) != 1 || out.Activities[0].ActivityID != 7 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetSearchActivityStatus(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(ActivityStatusResponse{
			ActivityID: 42,
			Action:     "delete",
			Status:     "completed",
			RemediationDetails: []RemediationDetail{{
				TenantID: 1, RawMessageID: "raw", Status: "success",
			}},
		})
	})
	out, err := c.GetSearchActivityStatus(context.Background(), 42)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/search/activities/42/status" {
		t.Fatalf("path: %q", gotPath)
	}
	if out.ActivityID != 42 || len(out.RemediationDetails) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetRemediationHistory(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"remediation_history":{"Would Remediate":"2026-09-10T09:52:50Z"},"folder_locations":[{"name":"inbox","display_name":"Inbox"}]}`))
	})
	out, err := c.GetRemediationHistory(context.Background(), 8427738389542485252)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/messages/8427738389542485252/remediation_history" {
		t.Fatalf("path: %q", gotPath)
	}
	if out.RemediationHistory["Would Remediate"] == "" {
		t.Fatalf("history: %+v", out.RemediationHistory)
	}
	if len(out.FolderLocations) != 1 || out.FolderLocations[0].DisplayName != "Inbox" {
		t.Fatalf("folders: %+v", out.FolderLocations)
	}
}

func TestListAbuseCampaigns(t *testing.T) {
	var gotFilter string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotFilter = r.URL.Query().Get("filter")
		_ = json.NewEncoder(w).Encode(PaginatedAbuseCampaigns{
			Campaigns:  []AbuseCampaignRef{{CampaignID: "camp-1"}},
			PageNumber: 1,
		})
	})
	filter := FormatTimeFilter("lastReportedTime", "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	out, err := c.ListAbuseCampaigns(context.Background(), ListAbuseCampaignsParams{
		Filter: filter, PageSize: 20, PageNumber: 1,
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotFilter != filter {
		t.Fatalf("filter: %q", gotFilter)
	}
	if len(out.Campaigns) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestGetAbuseCampaign(t *testing.T) {
	c := testClient(t, func(w http.ResponseWriter, _ *http.Request) {
		_ = json.NewEncoder(w).Encode(AbuseCampaignDetails{
			CampaignID: "camp-1", Subject: "spam", JudgementStatus: "Malicious",
		})
	})
	out, err := c.GetAbuseCampaign(context.Background(), "camp-1")
	if err != nil {
		t.Fatal(err)
	}
	if out.CampaignID != "camp-1" || out.JudgementStatus != "Malicious" {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestListUnanalyzedMailbox(t *testing.T) {
	var gotStart string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotStart = r.URL.Query().Get("start")
		_ = json.NewEncoder(w).Encode(AbuseMailboxUnanalyzedResponse{
			Results: []AbuseMailboxUnanalyzedMessage{{
				Subject: "fwd", AbxMessageID: 1, NotAnalyzedReason: "timeout",
			}},
		})
	})
	out, err := c.ListUnanalyzedMailbox(context.Background(), "2024-01-01T00:00:00Z", "2024-01-02T00:00:00Z")
	if err != nil {
		t.Fatal(err)
	}
	if gotStart != "2024-01-01T00:00:00Z" {
		t.Fatalf("start: %q", gotStart)
	}
	if len(out.Results) != 1 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestRemediateSearch(t *testing.T) {
	var gotMethod, gotPath string
	var gotBody RemediationRequest
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotMethod = r.Method
		gotPath = r.URL.Path
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(RemediationResponse{ActivityLogID: 99})
	})
	out, err := c.RemediateSearch(context.Background(), RemediationRequest{
		Action: "delete", Source: "abnormal", RemediationReason: "other",
		Messages: []MessageToRemediate{{TenantID: 1, RawMessageID: "m1", MailboxName: "inbox", NativeUserID: "u1", Subject: "s", Sender: "a@b.com", ReceivedTime: "2024-01-01T00:00:00Z"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if gotMethod != http.MethodPost || gotPath != "/v1/search/remediate" {
		t.Fatalf("method=%s path=%s", gotMethod, gotPath)
	}
	if gotBody.Action != "delete" || out.ActivityLogID != 99 {
		t.Fatalf("unexpected: body=%+v out=%+v", gotBody, out)
	}
}

func TestRemediateThreat(t *testing.T) {
	var gotBody PostThreatRequest
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewDecoder(r.Body).Decode(&gotBody)
		_ = json.NewEncoder(w).Encode(PostThreatResponse{ActionID: "act-1", StatusURL: "/status"})
	})
	out, err := c.RemediateThreat(context.Background(), "threat-1", "remediate")
	if err != nil {
		t.Fatal(err)
	}
	if gotBody.Action != "remediate" || out.ActionID != "act-1" {
		t.Fatalf("unexpected: body=%+v out=%+v", gotBody, out)
	}
}

func TestGetThreatActionStatus(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_ = json.NewEncoder(w).Encode(ThreatActionStatus{Status: "completed", Description: "done"})
	})
	out, err := c.GetThreatActionStatus(context.Background(), "threat-1", "act-1")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/threats/threat-1/actions/act-1" {
		t.Fatalf("path: %q", gotPath)
	}
	if out.Status != "completed" {
		t.Fatalf("unexpected: %+v", out)
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

func strPtr(s string) *string { return &s }
