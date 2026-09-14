package tools

import (
	"context"
	"testing"
)

func TestListAuditLogs(t *testing.T) {
	h := testHandlers()
	_, page, err := h.listAuditLogs(context.Background(), nil, auditLogsListInput{})
	if err != nil {
		t.Fatal(err)
	}
	if len(page.Items) != 1 || page.Items[0].UserEmail != "analyst@example.com" {
		t.Fatalf("unexpected: %+v", page)
	}
}
