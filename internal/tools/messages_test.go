package tools

import (
	"context"
	"testing"
)

func TestGetMessageRemediationHistoryRequiresID(t *testing.T) {
	h := testHandlers()
	_, _, err := h.getMessageRemediationHistory(context.Background(), nil, messageRemediationHistoryInput{})
	if err != errMessageIDRequired {
		t.Fatalf("got %v", err)
	}
}

func TestGetMessageRemediationHistory(t *testing.T) {
	h := testHandlers()
	_, out, err := h.getMessageRemediationHistory(context.Background(), nil, messageRemediationHistoryInput{MessageID: 123})
	if err != nil {
		t.Fatal(err)
	}
	if out.RemediationHistory["Auto-Remediated"] != "2024-01-01T00:00:00Z" {
		t.Fatalf("history: %+v", out.RemediationHistory)
	}
	if len(out.FolderLocations) != 1 || out.FolderLocations[0].Name != "junk" {
		t.Fatalf("folders: %+v", out.FolderLocations)
	}
}
