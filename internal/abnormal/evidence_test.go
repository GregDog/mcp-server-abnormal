package abnormal

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/GregDog/mcp-server-abnormal/internal/config"
)

func TestDownloadMessageEML(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		w.Header().Set("Content-Type", "message/rfc822")
		_, _ = w.Write([]byte("From: a@b.com\r\n"))
	})
	out, err := c.DownloadMessageEML(context.Background(), 12345)
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/messages/12345/download" {
		t.Fatalf("path: %q", gotPath)
	}
	if !strings.Contains(string(out.Data), "From:") {
		t.Fatalf("unexpected data: %q", out.Data)
	}
}

func TestDownloadSearchMessageEML(t *testing.T) {
	var gotPath, gotQuery string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		gotQuery = r.URL.RawQuery
		w.Header().Set("Content-Type", "message/rfc822")
		_, _ = w.Write([]byte("Subject: hello\r\n"))
	})
	out, err := c.DownloadSearchMessageEML(context.Background(), "cloud-1", "", "")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/search/messages/cloud-1/eml" {
		t.Fatalf("path: %q", gotPath)
	}
	if gotQuery != "" {
		t.Fatalf("query: %q", gotQuery)
	}
	if out.ContentType != "message/rfc822" {
		t.Fatalf("content type: %q", out.ContentType)
	}
}

func TestGetMessageAttachmentSignals(t *testing.T) {
	var gotPath string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotPath = r.URL.Path
		_, _ = w.Write([]byte(`{"risk_score":0.8}`))
	})
	out, err := c.GetMessageAttachmentSignals(context.Background(), 99, "invoice.pdf")
	if err != nil {
		t.Fatal(err)
	}
	if gotPath != "/v1/messages/99/attachment/invoice.pdf" {
		t.Fatalf("path: %q", gotPath)
	}
	if out["risk_score"] != 0.8 {
		t.Fatalf("unexpected: %+v", out)
	}
}

func TestDownloadSearchAttachment(t *testing.T) {
	var gotQuery string
	c := testClient(t, func(w http.ResponseWriter, r *http.Request) {
		gotQuery = r.URL.RawQuery
		_, _ = w.Write([]byte("%PDF"))
	})
	_, err := c.DownloadSearchAttachment(context.Background(), SearchAttachmentDownloadParams{
		MessageID: 1, AttachmentName: "x.pdf", TenantID: 2,
		RawMessageID: "raw-1", NativeUserID: "native-1", RecipientMailbox: "user@example.com",
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{"message_id=1", "attachment_name=x.pdf", "tenant_id=2", "raw_message_id=raw-1", "native_user_id=native-1", "recipient_mailbox=user%40example.com"} {
		if !strings.Contains(gotQuery, want) {
			t.Fatalf("query %q missing %q", gotQuery, want)
		}
	}
}

func TestDownloadEvidenceTooLarge(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		_, _ = w.Write(make([]byte, 32))
	}))
	t.Cleanup(srv.Close)
	c, err := New(config.Config{APIToken: "t", BaseURL: srv.URL + "/v1", MaxEvidenceBytes: 16})
	if err != nil {
		t.Fatal(err)
	}
	_, err = c.DownloadMessageEML(context.Background(), 1)
	if err == nil || !strings.Contains(err.Error(), "exceeds max size") {
		t.Fatalf("expected size error, got %v", err)
	}
}
