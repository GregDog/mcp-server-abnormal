package tools

import (
	"context"
	"testing"
)

func TestSearchRemediateDisabled(t *testing.T) {
	h := testHandlers()
	_, _, err := h.searchRemediate(context.Background(), nil, searchRemediateInput{
		Action: "delete", RemediationReason: "other", Confirm: true,
		Messages: []messageToRemediateInput{{TenantID: 1, RawMessageID: "m1", MailboxName: "inbox", NativeUserID: "u1", Subject: "s", Sender: "a@b.com", ReceivedTime: "2024-01-01T00:00:00Z"}},
	})
	if err != errResponseDisabled {
		t.Fatalf("got %v", err)
	}
}

func TestSearchRemediatePreview(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.searchRemediate(context.Background(), nil, searchRemediateInput{
		Action: "delete", RemediationReason: "other",
		Messages: []messageToRemediateInput{{TenantID: 1, RawMessageID: "m1", MailboxName: "inbox", NativeUserID: "u1", Subject: "s", Sender: "a@b.com", ReceivedTime: "2024-01-01T00:00:00Z"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != errConfirmationRequired || out.Confirmed {
		t.Fatalf("unexpected preview: %+v", out)
	}
}

func TestSearchRemediateConfirm(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.searchRemediate(context.Background(), nil, searchRemediateInput{
		Confirm: true, Action: "delete", RemediationReason: "other",
		Messages: []messageToRemediateInput{{TenantID: 1, RawMessageID: "m1", MailboxName: "inbox", NativeUserID: "u1", Subject: "s", Sender: "a@b.com", ReceivedTime: "2024-01-01T00:00:00Z"}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Confirmed || out.ActivityLogID != 42 {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestSearchRemediateRequiresMessages(t *testing.T) {
	h := testResponseHandlers()
	_, _, err := h.searchRemediate(context.Background(), nil, searchRemediateInput{
		Confirm: true, Action: "delete", RemediationReason: "other",
	})
	if err != errMessagesRequired {
		t.Fatalf("got %v", err)
	}
}

func TestSearchRemediateMoveRequiresFolder(t *testing.T) {
	h := testResponseHandlers()
	_, _, err := h.searchRemediate(context.Background(), nil, searchRemediateInput{
		Confirm: true, Action: "move_to_inbox", RemediationReason: "other",
		Messages: []messageToRemediateInput{{TenantID: 1, RawMessageID: "m1", MailboxName: "inbox", NativeUserID: "u1", Subject: "s", Sender: "a@b.com", ReceivedTime: "2024-01-01T00:00:00Z"}},
	})
	if err != errTargetFolderRequired {
		t.Fatalf("got %v", err)
	}
}

func TestThreatRemediateDisabled(t *testing.T) {
	h := testHandlers()
	_, _, err := h.threatRemediate(context.Background(), nil, threatRemediateInput{
		ID: "threat-1", Action: "remediate", Confirm: true,
	})
	if err != errResponseDisabled {
		t.Fatalf("got %v", err)
	}
}

func TestThreatRemediatePreview(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.threatRemediate(context.Background(), nil, threatRemediateInput{
		ID: "threat-1", Action: "remediate",
	})
	if err != nil {
		t.Fatal(err)
	}
	if out.Error != errConfirmationRequired || out.Confirmed {
		t.Fatalf("unexpected preview: %+v", out)
	}
}

func TestThreatRemediateConfirm(t *testing.T) {
	h := testResponseHandlers()
	_, out, err := h.threatRemediate(context.Background(), nil, threatRemediateInput{
		ID: "threat-1", Action: "remediate", Confirm: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !out.Confirmed || out.ActionID != "action-1" {
		t.Fatalf("unexpected result: %+v", out)
	}
}

func TestThreatRemediateInvalidAction(t *testing.T) {
	h := testResponseHandlers()
	_, _, err := h.threatRemediate(context.Background(), nil, threatRemediateInput{
		ID: "threat-1", Action: "delete", Confirm: true,
	})
	if err != errThreatActionRequired {
		t.Fatalf("got %v", err)
	}
}
